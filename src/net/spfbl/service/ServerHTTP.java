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
package net.spfbl.service;

import net.spfbl.spf.SPF;
import com.sun.mail.smtp.SMTPAddressFailedException;
import com.sun.mail.util.MailConnectException;
import com.sun.mail.util.SocketConnectException;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import net.spfbl.core.Server;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.BindException;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.NoRouteToHostException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.text.DateFormat;
import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.SendFailedException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.naming.CommunicationException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.ServiceUnavailableException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import net.spfbl.core.Analise;
import net.spfbl.core.BinarySemaphore;
import net.spfbl.data.Block;
import net.spfbl.core.Client;
import net.spfbl.core.Core;
import net.spfbl.core.Defer;
import static net.spfbl.core.Filterable.Filter.ABUSE_SUBMISSION;
import net.spfbl.core.Peer;
import net.spfbl.core.Period;
import net.spfbl.core.ProcessException;
import net.spfbl.core.Regex;
import static net.spfbl.core.Regex.isHostname;
import static net.spfbl.core.Regex.isValidEmail;
import static net.spfbl.core.Regex.isValidIP;
import net.spfbl.core.Reverse;
import net.spfbl.core.User;
import net.spfbl.core.User.Query;
import net.spfbl.data.Abuse;
import net.spfbl.data.AddressSet;
import net.spfbl.data.CIDR;
import net.spfbl.data.Generic;
import net.spfbl.data.Ignore;
import net.spfbl.data.NoReply;
import net.spfbl.data.Provider;
import net.spfbl.data.FQDN;
import net.spfbl.data.Licence;
import net.spfbl.data.Reputation;
import net.spfbl.data.Reputation.Flag;
import static net.spfbl.data.Reputation.Flag.BENEFICIAL;
import static net.spfbl.data.Reputation.Flag.HARMFUL;
import net.spfbl.data.Trap;
import net.spfbl.data.White;
import net.spfbl.spf.SPF.Qualifier;
import static net.spfbl.spf.SPF.Qualifier.FAIL;
import static net.spfbl.spf.SPF.Qualifier.PASS;
import static net.spfbl.spf.SPF.Qualifier.SOFTFAIL;
import net.spfbl.spf.SPF.Status;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv6;
import org.apache.commons.lang3.LocaleUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.shredzone.acme4j.challenge.Http01Challenge;

/**
 * Servidor de consulta em SPF.
 *
 * Este serviço responde a consulta e finaliza a conexão logo em seguida.
 *
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public final class ServerHTTP extends Server {

    private final String HOSTNAME;
    private final int PORT;
    private final ExecutorService EXECUTOR;
    private final HttpServer SERVER;
    private final int PORTS;
    private HttpsServer SERVERS = null;

    private static byte CONNECTION_LIMIT = 8;
    
    public static byte getConnectionLimit() {
        return CONNECTION_LIMIT;
    }

    public static void setConnectionLimit(String limit) {
        if (limit != null && limit.length() > 0) {
            try {
                setConnectionLimit(Integer.parseInt(limit));
            } catch (Exception ex) {
                Server.logError("invalid HTTP connection limit '" + limit + "'.");
            }
        }
    }

    public static void setConnectionLimit(int limit) {
        if (limit < 1 || limit > Byte.MAX_VALUE) {
            Server.logError("invalid HTTP connection limit '" + limit + "'.");
        } else {
            CONNECTION_LIMIT = (byte) limit;
        }
    }

    /**
     * Configuração e intanciamento do servidor.
     *
     * @param port a porta HTTPS a ser vinculada.
     * @throws java.io.IOException se houver falha durante o bind.
     */
    public ServerHTTP(String hostname, int port, int ports) throws Exception {
        super("SERVERHTP");
        HOSTNAME = hostname;
        PORT = port;
        PORTS = ports;
        setPriority(Thread.NORM_PRIORITY);
        System.setProperty("sun.net.httpserver.maxReqTime", "10");
        System.setProperty("sun.net.httpserver.maxRspTime", "60");
        // Criando conexões.
        Server.logInfo("binding HTTP socket on port " + port + "...");
        SERVER = HttpServer.create(new InetSocketAddress(port), 0);
        SERVER.createContext("/", new AccessHandler(false));
        EXECUTOR = new ExecutorHTTP();
        SERVER.setExecutor(EXECUTOR);
    }

    public int getPort() {
        return PORT;
    }

    public String getURL() {
        return getURL(null);
    }

    public String getURL(Locale locale) {
        if (HOSTNAME == null) {
            return null;
        } else {
            String lang = locale == null ? null : locale.getLanguage();
            if (lang == null || lang.isEmpty()) {
                return "http://" + HOSTNAME + (PORT == 80 ? "" : ":" + PORT) + "/";
            } else {
                return "http://" + HOSTNAME + (PORT == 80 ? "" : ":" + PORT) + "/" + lang + "/";
            }
        }
    }

    public int getSecuredPort() {
        return PORTS;
    }

    public String getSecuredURL() {
        return getSecuredURL(null);
    }

    public String getSecuredURL(Locale locale) {
        if (HOSTNAME == null) {
            return null;
        } else if (SERVERS == null || Core.isExpiringCertificate(HOSTNAME)) {
            String lang = locale == null ? null : locale.getLanguage();
            if (lang == null || lang.isEmpty()) {
                return "http://" + HOSTNAME + (PORT == 80 ? "" : ":" + PORT) + "/";
            } else {
                return "http://" + HOSTNAME + (PORT == 80 ? "" : ":" + PORT) + "/" + lang + "/";
            }
        } else {
            String lang = locale == null ? null : locale.getLanguage();
            if (lang == null || lang.isEmpty()) {
                return "https://" + HOSTNAME + (PORTS == 443 ? "" : ":" + PORTS) + "/";
            } else {
                return "https://" + HOSTNAME + (PORTS == 443 ? "" : ":" + PORTS) + "/" + lang + "/";
            }
        }
    }

    private static String getOrigin(String address, Client client, String user) {
        if (client == null) {
            return getOrigin(address, (String) null, user);
        } else {
            return getOrigin(address, client.getDomain(), user);
        }
    }
    
    private static String getOrigin(String address, String client, String user) {
        String result = address;
        result += (client == null ? "" : " " + client);
        result += (user == null ? "" : " " + user);
        return result;
    }

    private static Peer getPeer(HttpExchange exchange) {
        InetSocketAddress socketAddress = exchange.getRemoteAddress();
        InetAddress address = socketAddress.getAddress();
        return Peer.get(address);
    }

    private static Client getClient(HttpExchange exchange) {
        InetSocketAddress socketAddress = exchange.getRemoteAddress();
        InetAddress address = socketAddress.getAddress();
        return Client.get(address);
    }

    private static String getRemoteAddress(HttpExchange exchange) {
        InetSocketAddress socketAddress = exchange.getRemoteAddress();
        InetAddress address = socketAddress.getAddress();
        return address.getHostAddress();
    }

    @SuppressWarnings("unchecked")
    private static HashMap<String,Object> getParameterMap(HttpExchange exchange) throws IOException {
        InputStreamReader isr = new InputStreamReader(exchange.getRequestBody(), UTF_8);
        BufferedReader br = new BufferedReader(isr);
        String query = br.readLine();
        return getParameterMap(query);
    }

    @SuppressWarnings("unchecked")
    private static HashMap<String, Object> getParameterMap(String query) throws UnsupportedEncodingException {
        if (query == null || query.length() == 0) {
            return null;
        } else {
            Integer otp = null;
            String password = null;
            Long begin = null;
            Long timekey = null;
            TreeSet<String> identifierSet = new TreeSet<>();
            HashMap<String, Object> map = new HashMap<>();
            String pairs[] = query.split("[&]");
            for (String pair : pairs) {
                String param[] = pair.split("[=]");
                String key = null;
                String value = null;
                if (param.length > 0) {
                    try {
                        key = URLDecoder.decode(
                                param[0],
                                System.getProperty("file.encoding")
                        );
                    } catch (Exception ex) {
                        key = param[0];
                    }
                }
                if (param.length > 1) {
                    try {
                        value = URLDecoder.decode(
                                param[1],
                                System.getProperty("file.encoding")
                        );
                    } catch (Exception ex) {
                        key = param[1];
                    }
                }
                if ("identifier".equals(key)) {
                    identifierSet.add(value);
                } else if ("otp".equals(key)) {
                    try {
                        otp = Integer.parseInt(value);
                    } catch (NumberFormatException ex) {
                        // Ignore.
                    }
                } else if ("begin".equals(key)) {
                    try {
                        begin = Long.parseLong(value);
                    } catch (NumberFormatException ex) {
                        // Ignore.
                    }
                } else if ("timekey".equals(key)) {
                    try {
                        timekey = Long.parseLong(value);
                    } catch (NumberFormatException ex) {
                        // Ignore.
                    }
                } else if ("filter".equals(key)) {
                    if (value == null) {
                        map.put(key, "");
                    } else {
                        value = Core.removerAcentuacao(value);
                        value = value.replace(" ", "");
                        value = value.toLowerCase();
                        if (value.length() > 0) {
                            map.put(key, value);
                        }
                    }
                } else {
                    map.put(key, value);
                }
            }
            if (otp != null) {
                map.put("otp", otp);
            }
            if (password != null) {
                map.put("password", password);
            }
            if (begin != null) {
                map.put("begin", begin);
            }
            if (timekey != null) {
                map.put("timekey", timekey);
            }
            if (!identifierSet.isEmpty()) {
                map.put("identifier", identifierSet);
            }
            return map;
        }
    }

    private static class Language implements Comparable<Language> {

        private final Locale locale;
        private final float q;

        private Language(String language) {
            language = language.replace('-', '_');
            int index = language.indexOf(';');
            if (index == -1) {
                locale = LocaleUtils.toLocale(language);
                q = 1.0f;
            } else {
                String value = language.substring(0, index).trim();
                locale = LocaleUtils.toLocale(value);
                float qFloat;
                try {
                    index = language.lastIndexOf('=') + 1;
                    value = language.substring(index).trim();
                    qFloat = Float.parseFloat(value);
                } catch (NumberFormatException ex) {
                    qFloat = 0.0f;
                }
                q = qFloat;
            }
        }

        public Locale getLocale() {
            return locale;
        }

        public boolean isLanguage(String language) {
            return locale.getLanguage().equals(language);
        }

        @Override
        public int compareTo(Language other) {
            if (other == null) {
                return -1;
            } else if (this.q < other.q) {
                return 1;
            } else {
                return -1;
            }
        }

        @Override
        public String toString() {
            return locale.getLanguage();
        }
    }

    private static Locale getLocale(String acceptLanguage) {
        if (acceptLanguage == null) {
            return Locale.US;
        } else {
            TreeSet<Language> languageSet = new TreeSet<>();
            StringTokenizer tokenizer = new StringTokenizer(acceptLanguage, ",");
            while (tokenizer.hasMoreTokens()) {
                try {
                    Language language = new Language(tokenizer.nextToken());
                    languageSet.add(language);
                } catch (Exception ex) {
                }
            }
            for (Language language : languageSet) {
                if (language.isLanguage("en")) {
                    return language.getLocale();
                } else if (language.isLanguage("pt")) {
                    return language.getLocale();
                }
            }
            return Locale.US;
        }
    }

    private static Locale getLocale(HttpExchange exchange) {
        Headers headers = exchange.getRequestHeaders();
        String acceptLanguage = headers.getFirst("Accept-Language");
        return getLocale(acceptLanguage);
    }
    
    private static User getUser(HttpExchange exchange, boolean secured) {
        String email = getUserEmail(exchange, secured);
        return User.getExact(email);
    }

    private static String getUserEmail(HttpExchange exchange, boolean secured) {
        Headers headers = exchange.getRequestHeaders();
        String cookies = headers.getFirst("Cookie");
        if (cookies == null) {
            return null;
        } else {
            StringTokenizer tokenizer = new StringTokenizer(cookies, ";");
            while (tokenizer.hasMoreTokens()) {
                try {
                    String cookie = tokenizer.nextToken().trim();
                    if (cookie.startsWith("login=")) {
                        int index = cookie.indexOf('=');
                        String registry = Server.decrypt(cookie.substring(index + 1).trim());
                        StringTokenizer tokenizer2 = new StringTokenizer(registry, " ");
                        Date date = Server.parseTicketDate(tokenizer2.nextToken());
                        if (System.currentTimeMillis() - date.getTime() < 604800000) {
                            String email = tokenizer2.nextToken();
                            if (secured) {
                                return email;
                            } else {
                                InetAddress ticketAddress = InetAddress.getByName(tokenizer2.nextToken());
                                if (exchange.getRemoteAddress().getAddress().equals(ticketAddress)) {
                                    return email;
                                }
                            }
                        }
                    }
                } catch (Exception ex) {
                    Server.logError("error when get browser cookies.");
                }
            }
            return null;
        }
    }

    private static final SimpleDateFormat DATE_FORMAT_COOKIE = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US);

    private static String getDateExpiresCookie() {
        long time = System.currentTimeMillis() + 604800000;
        Date date = new Date(time);
        return DATE_FORMAT_COOKIE.format(date);
    }
    
    private static void setUser(HttpExchange exchange, User user) throws ProcessException {
        if (user != null) {
            setUser(exchange, user.getEmail());
        }
    }

    private static void setUser(HttpExchange exchange, String userEmail) throws ProcessException {
        if (userEmail != null) {
            Headers headers = exchange.getResponseHeaders();
            InetAddress remoteAddress = exchange.getRemoteAddress().getAddress();
            String registry = Server.getNewTicketDate() + " " + userEmail + " " + remoteAddress.getHostAddress();
            String ticket = Server.encrypt(registry);
            String cookie = "login=" + ticket + "; expires=" + getDateExpiresCookie() + "; path=/";
            headers.add("Set-Cookie", cookie);
            Server.logTrace("Set-Cookie: " + cookie);
        }
    }

    private static String getTempoPunicao(long failTime) {
        if ((failTime /= 1000) < 60) {
            return failTime + (failTime > 1 ? " segundos" : " segundo");
        } else if ((failTime /= 60) < 60) {
            return failTime + (failTime > 1 ? " minutos" : " minuto");
        } else if ((failTime /= 60) < 24) {
            return failTime + (failTime > 1 ? " dias" : " dia");
        } else {
            failTime /= 24;
            return failTime + (failTime > 1 ? " semanas" : " semana");
        }
    }

    private static final Regex URL_SIGNATURE_PATTERN = new Regex("^"
            + "[0-9a-zA-Z_-]+\\.url"
            + "$"
    );

    private static boolean isSignatureURL(String token) {
        if (token == null) {
            return false;
        } else if (token.endsWith(".url")) {
            return URL_SIGNATURE_PATTERN.matches(token);
        } else {
            return false;
        }
    }

    private static boolean isValidDomainOrIP(String token) {
        if (isSignatureURL(token)) {
            return true;
        } else if (Server.isValidTicket(token)) {
            return false;
        } else if (isValidIP(token)) {
            return true;
        } else if (isHostname(token)) {
            return true;
        } else {
            return false;
        }
    }

    private Http01Challenge CHALLENGE = null;

    public void setChallenge(Http01Challenge challenge) {
        this.CHALLENGE = challenge;
    }

    private static final File FOLDER = new File("./web/");

    public static File getWebFile(String name) {
        if (name.contains("../")) {
            /**
             * Restriction for security. The user cannot access other files of
             * OS.
             */
            return null;
        } else {
            File file = new File(FOLDER, name);
            if (file.exists()) {
                return file;
            } else {
                return null;
            }
        }
    }

    private static int CONNECTION_ID = 0;
    private static final DecimalFormat FORMAT_ID = new DecimalFormat("00000");

    private static synchronized String newConnectionName() {
        if (CONNECTION_ID > 99999) {
            CONNECTION_ID = 0;
        }
        return "HTTP" + FORMAT_ID.format(++CONNECTION_ID);
    }
    
    private static final HashMap<String,Long> HIGH_FREQUENCY_MAP = new HashMap<>();
    
    public static synchronized TreeSet<String> getHighFrequencyKeySet() {
        TreeSet<String> resultSet = new TreeSet<>();
        resultSet.addAll(HIGH_FREQUENCY_MAP.keySet());
        return resultSet;
    }
    
    private static synchronized Long getHighFrequencyTime(String address) {
        if (address == null) {
            return null;
        } else {
            return HIGH_FREQUENCY_MAP.get(address);
        }
    }
    
    private static synchronized Long putHighFrequency(String address, Long lastTime) {
        if (address == null) {
            return null;
        } else if (lastTime == null) {
            return null;
        } else {
            return HIGH_FREQUENCY_MAP.put(address, lastTime);
        }
    }
    
    private static synchronized boolean dropHighFrequencyAddress(String address) {
        if (address == null) {
            return false;
        } else {
            HIGH_FREQUENCY_MAP.remove(address);
            return true;
        }
    }
    
    private static boolean addHighFrequencyAddress(String address) {
        if (address == null) {
            return false;
        } else {
            putHighFrequency(address, System.currentTimeMillis());
            return true;
        }
    }
    
    public static TreeSet<String> getHighFrequencySet() {
        AddressSet highFrequencySet = new AddressSet();
        for (String ip : getHighFrequencyKeySet()) {
            highFrequencySet.add(ip);
        }
        TreeSet<String> resultSet = new TreeSet<>();
        for (String cidr : highFrequencySet.getAllLegacy()) {
            if (cidr.startsWith("CIDR=")) {
                cidr = cidr.substring(5);
            }
            resultSet.add(cidr);
        }
        return resultSet;
    }
    
    private static final HashMap<String,Period> PERIOD_MAP = new HashMap<>();
    
    private static synchronized Period putPeriod(String key, Period period) {
        if (key == null) {
            return null;
        } else if (period == null) {
            return null;
        } else {
            return PERIOD_MAP.put(key, period);
        }
    }
    
    private static synchronized Period getPeriod(String key) {
        if (key == null) {
            return null;
        } else {
            Period period = PERIOD_MAP.get(key);
            if (period == null) {
                period = new Period();
                PERIOD_MAP.put(key, period);
            }
            return period;
        }
    }
    
    public static synchronized Period removePeriod(String key) {
        if (key == null) {
            return null;
        } else {
            return PERIOD_MAP.remove(key);
        }
    }
    
    public static synchronized TreeSet<String> getPeriodKeySet() {
        TreeSet<String> addressSet = new TreeSet<>();
        addressSet.addAll(PERIOD_MAP.keySet());
        return addressSet;
    }
    
    public static TreeSet<String> getAbusingSet() {
        AddressSet abusingSet = new AddressSet();
        for (String address : getPeriodKeySet()) {
            Period period = getPeriod(address);
            if (period.isExpired()) {
                removePeriod(address);
            } else if (period.isAbusing(64, 432000000, 3000)) {
                if (address.contains(":")) {
                    abusingSet.add(address + "/48");
                } else {
                    abusingSet.add(address + "/24");
                }
            }
        }
        TreeSet<String> resultSet = new TreeSet<>();
        for (String cidr : abusingSet.getAllLegacy()) {
            if (cidr.startsWith("CIDR=")) {
                cidr = cidr.substring(5);
            }
            resultSet.add(cidr);
        }
        return resultSet;
    }
    
    public static void store() {
        long time = System.currentTimeMillis();
        File file = new File("./data/http.txt");
        try (FileWriter writer = new FileWriter(file)) {
            for (String address : getPeriodKeySet()) {
                Period period = getPeriod(address);
                if (period != null) {
                    writer.append(address);
                    writer.append(' ');
                    writer.append(period.storeLine());
                    writer.append('\n');
                }
            }
            for (String address : getHighFrequencyKeySet()) {
                Long lastTime = getHighFrequencyTime(address);
                if (lastTime != null) {
                    if ((System.currentTimeMillis() - lastTime) > Server.WEEK_TIME) {
                        dropHighFrequencyAddress(address);
                    } else {
                        writer.append(address);
                        writer.append(' ');
                        writer.append(lastTime.toString());
                        writer.append('\n');
                    }
                }
            }
            Server.logStore(time, file);
        } catch (Exception ex) {
            Server.logError(ex);
        }
    }
    
    public static void load() {
        long time = System.currentTimeMillis();
        File file = new File("./data/http.txt");
        if (file.exists()) {
            String line;
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                while ((line = reader.readLine()) != null) {
                    try {
                        int index = line.indexOf(' ');
                        String address = line.substring(0, index);
                        line = line.substring(index + 1);
                        Period period = Period.loadLine(line);
                        putPeriod(address, period);
                        Long lastTime = Core.parseLong(line, 10);
                        putHighFrequency(address, lastTime);
                    } catch (Exception ex) {
                        Server.logError(ex);
                    }
                }
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }

    private class AccessHandler implements HttpHandler {

        private final boolean SECURED;

        private AccessHandler(boolean secured) {
            this.SECURED = secured;
        }

        @Override
        public void handle(HttpExchange exchange) {
            try {
                long time = System.currentTimeMillis();
                Thread thread = Thread.currentThread();
                if (!thread.getName().startsWith("HTTP")) {
                    thread.setName(newConnectionName());
                }
                if (SECURED) {
                    Headers headers = exchange.getResponseHeaders();
                    if (Core.isExpiringCertificate(HOSTNAME)) {
                        headers.set("Strict-Transport-Security", "max-age=604800"); // 1 week
                    } else {
                        headers.set("Strict-Transport-Security", "max-age=31536000"); // 1 year
                    }
                }
                InetSocketAddress socketAddress = exchange.getRemoteAddress();
                InetAddress inetAddress = socketAddress.getAddress();
                String remoteAddress = inetAddress.getHostAddress();
                URI uri = exchange.getRequestURI();
                String command = uri.toString();
                int index = command.indexOf('?');
                String parameterURL = null;
                if (index != -1) {
                    parameterURL = command.substring(index + 1);
                    command = command.substring(0, index);
                }
                Licence.Tuple licenceTuple = null;
                Licence.Message licenceMessage = null;
                if (command.startsWith("/licence/")) {
                    String ticket = command.substring(9);
                    licenceTuple = Licence.loadLicence(ticket);
                } else if (command.startsWith("/message/")) {
                    String ticket = command.substring(9);
                    licenceMessage = Licence.loadMessage(ticket);
                }
                String userEmail;
                if (licenceTuple != null) {
                    userEmail = licenceTuple.consumeAndGetUserEmail(inetAddress);
                } else if (licenceMessage != null) {
                    userEmail = licenceMessage.consumeAndGetUserEmail();
                } else if ((userEmail = getUserEmail(exchange, SECURED)) != null) {
                    Server.logTrace("logged as " + userEmail);
                }
                boolean abusing;
                boolean banned;
                if (userEmail == null) {
                    Period period = getPeriod(remoteAddress);
                    if (period == null) {
                        abusing = false;
                        banned = false;
                    } else if (period.isAbusing(128, 432000000, 10000)) {
                        abusing = true;
                        banned = true;
                    } else {
                        period.registerEvent();
                        abusing = period.isAbusing(32, 5000);
                        banned = false;
                    }
                } else {
                    removePeriod(remoteAddress);
                    abusing = false;
                    banned = false;
                }
                if (banned) {
                    exchange.close();
                    Server.log(
                            time,
                            Core.Level.DEBUG,
                            "ABUSE",
                            (Long) null,
                            "the remote IP " + remoteAddress + " was banned.",
                            null
                    );
                } else if (abusing) {
                    int code = 429;
                    String result = "Warning! Your IP " + remoteAddress
                            + " will be banned because of too many requests.";
                    String tag = "ABUSE";
                    String type = "text/plain";
                    try {
                        response(code, type, result, exchange);
                        result = code + " " + type + " " + result;
                    } catch (IOException ex) {
                        result = ex.getMessage();
                    }
                    Server.logQuery(time, tag, remoteAddress, null, result, null);
                } else {
                    int code;
                    String result;
                    String tag;
                    String type;
                    String request = exchange.getRequestMethod();
                    HashMap<String,Object> parameterMap = getParameterMap(exchange);
                    if (parameterURL != null) {
                        StringTokenizer tokenizer = new StringTokenizer(parameterURL, "&");
                        while (tokenizer.hasMoreTokens()) {
                            String token = tokenizer.nextToken();
                            index = token.indexOf('=');
                            if (index != -1) {
                                String key = token.substring(0, index);
                                String value = token.substring(index + 1);
                                value = URLDecoder.decode(value, "UTF-8");
                                if (parameterMap == null) {
                                    parameterMap = new HashMap<>();
                                }
                                if (key.equals("begin") || key.equals("timekey")) {
                                    try {
                                        parameterMap.put(key, Long.parseLong(value));
                                    } catch (NumberFormatException ex) {
                                        // Do nothing.
                                    }
                                } else {
                                    parameterMap.put(key, value);
                                }
                            }
                        }
                    }
                    String origin;
                    if (licenceTuple != null && request.equals("GET")) {
                        JSONObject json = new JSONObject();
                        if (licenceTuple.isExpired()) {
                            json.put("result", "permerror");
                            json.put("information", "expired licence");
                        } else if (userEmail == null && !licenceTuple.isValidClient(inetAddress)) {
                            json.put("result", "permerror");
                            json.put("information", "unauthorized client");
                        } else if (userEmail == null && licenceTuple.isWithoutFuel()) {
                            json.put("result", "permerror");
                            json.put("information", "without fuel");
                        } else if (userEmail == null) {
                            json.put("result", "permerror");
                            json.put("information", "invalid user");
                        } else if (parameterMap == null || parameterMap.isEmpty()) {
                            json.put("result", "permerror");
                            json.put("information", "parameters not defined");
                        } else if ((licenceMessage = licenceTuple.newMessage(parameterMap)) == null) {
                            json.put("result", "permerror");
                            json.put("information", "invalid parameters");
                        } else {
                            addHighFrequencyAddress(remoteAddress);
                            json.put("result", licenceMessage.getResult());
                            json.put("information", licenceMessage.getInformation());
                            json.put("messageURL", licenceMessage.getMessageURL());
                        }
                        String client = licenceTuple.getClient();
                        origin = getOrigin(remoteAddress, client, userEmail);
                        tag = "LICEN";
                        type = "application/json";
                        code = 200;
                        result = json.toJSONString();
                    } else if (licenceMessage != null && request.equals("GET")) {
                        JSONObject json = new JSONObject();
                        String function = parameterMap == null ? null : (String) parameterMap.get("function");
                        if (function == null) {
                            licenceMessage.write(json);
                        } else if (function.equals("block")) {
                            json.put("result", "successful");
                            if (licenceMessage.block()) {
                                json.put("information", "the sender has just been blocked");
                            } else {
                                json.put("information", "the sender was already blocked");
                            }
                        } else if (function.equals("white")) {
                            json.put("result", "successful");
                            if (licenceMessage.white()) {
                                json.put("information", "the sender has just been whitelisted");
                            } else {
                                json.put("information", "the sender was already whitelisted");
                            }
                        } else {
                            json.put("result", "unsuccessful");
                            json.put("information", "function not defined");
                        }
                        String client = licenceMessage.getClient(inetAddress);
                        origin = getOrigin(remoteAddress, client, userEmail);
                        tag = "LICEN";
                        type = "application/json";
                        code = 200;
                        result = json.toJSONString();
                    } else {
                        Locale locale = getLocale(exchange);
                        TimeZone timeZone = TimeZone.getDefault();
                        File file;
                        User user = User.getExact(userEmail);
                        Client client = getClient(exchange);
                        origin = getOrigin(remoteAddress, client, userEmail);
                        Server.logTrace(
                                time,
                                (SECURED ? "HTTPS " : "HTTP ") + request + " " + command
                                + (parameterMap == null ? "" : " " + parameterMap)
                        );
                        int langIndex = command.indexOf('/', 1);
                        if (langIndex == 3 || langIndex == 4) {
                            // Language mode.
                            String lang = command.substring(1, langIndex).toLowerCase();
                            if (lang.equals("en")) {
                                locale = Locale.UK;
                                timeZone = TimeZone.getTimeZone("Europe/London");
                            } else if (lang.equals("pt")) {
                                locale = new Locale("pt", "BR");
                                timeZone = TimeZone.getTimeZone("America/Sao_Paulo");
                            } else {
                                locale = Locale.US;
                                timeZone = TimeZone.getTimeZone("America/New_York");
                            }
                            command = command.substring(langIndex);
                        } else if (user != null) {
                            locale = user.getLocale();
                            timeZone = user.getTimeZone();
                        }
                        command = URLDecoder.decode(command, "UTF-8");
                        if (!Core.hasHostname()) {
                            type = "text/html";
                            tag = "ERROR";
                            code = 500;
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                result = getMessageHMTL(
                                        locale,
                                        "Página de erro do SPFBL",
                                        "O hostname deste sistema não foi definido no arquivo de configuração."
                                );
                            } else {
                                result = getMessageHMTL(
                                        locale,
                                        "SPFBL error page",
                                        "The hostname of this system has not been defined in the configuration file."
                                );
                            }
                        } else if (request.equals("POST")) {
                            if (command.equals("/")) {
                                type = "text/html";
                                tag = "MMENU";
                                code = 200;
                                String message;
                                if (parameterMap != null && parameterMap.containsKey("query")) {
                                    String query = (String) parameterMap.get("query");
                                    if (query != null) {
                                        query = query.replace(" ", "").trim();
                                    }
                                    if (isValidIP(query)) {
                                        query = Subnet.normalizeIP(query);
                                        result = getRedirectHTML(locale, "/" + locale.getLanguage() + "/" + query);
                                    } else if (isHostname(query)) {
                                        query = Domain.normalizeHostname(query, false);
                                        result = getRedirectHTML(locale, "/" + locale.getLanguage() + "/" + query);
                                    } else if (Core.isValidURL(query)) {
                                        query = URLDecoder.decode(query, "UTF-8");
                                        query = Core.compressAsString(query) + ".url";
                                        result = getRedirectHTML(locale, "/" + locale.getLanguage() + "/" + query);
                                    } else {
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Consulta inválida";
                                        } else {
                                            message = "Invalid query";
                                        }
                                        result = getMainHTML(locale, message, remoteAddress);
                                    }
                                } else {
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        message = "Página principal do serviço SPFBL";
                                    } else {
                                        message = "This is SPFBL's main page";
                                    }
                                    result = getMainHTML(locale, message, remoteAddress);
                                }
                            } else if (command.equals("/robots.txt")) {
                                type = "text/plain";
                                tag = "HTTPC";
                                code = 403;
                                result = "Forbidden\n";
                            } else if (isValidEmail(command.substring(1).trim())) {
                                String message;
                                userEmail = command.substring(1).toLowerCase().trim();
                                User userLogin = getUser(exchange, SECURED);
                                if (userLogin != null && !userLogin.hasTransitionOTP() && userLogin.isEmail(userEmail)) {
                                    Long begin = (Long) (parameterMap == null ? null : parameterMap.get("begin"));
                                    String filter = (String) (parameterMap == null ? null : parameterMap.get("filter"));
                                    message = getControlPanel(locale, timeZone, userLogin, begin, filter);
                                } else if ((userLogin = User.get(userEmail)) == null) {
                                    String title;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        title = "Login do SPFBL";
                                    } else {
                                        title = "SPFBL Login";
                                    }
                                    String text;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        text = "Usuário inexistente.";
                                    } else {
                                        text = "Non-existent user.";
                                    }
                                    message = getMessageHMTL(locale, title, text);
                                } else if (userLogin.hasPassword()) {
                                    if (parameterMap != null && parameterMap.containsKey("password")) {
                                        String password = (String) parameterMap.get("password");
                                        if (userLogin.isValidPassword(password)) {
                                            setUser(exchange, userLogin);
                                            locale = userLogin.getLocale();
                                            message = getRedirectHTML(locale, command);
                                        } else if (userLogin.tooManyFailsPassword()) {
                                            long failTime = userLogin.getFailTimePassword();
                                            int pageTime = (int) (failTime / 1000) + 1;
                                            String tempoPunicao = getTempoPunicao(failTime);
                                            String title;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                title = "Login do SPFBL";
                                            } else {
                                                title = "SPFBL Login";
                                            }
                                            String text;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                text = "Conta temporariamente bloqueada por excesso de logins fracassados.\n"
                                                        + "Aguarde cerca de " + tempoPunicao + " para tentar novamente.";
                                            } else {
                                                text = "Account temporarily blocked due to overflow of failed logins.\n"
                                                        + "Wait for about " + tempoPunicao + " to try again.";
                                            }
                                            message = getRedirectHMTL(
                                                    locale,
                                                    title,
                                                    text,
                                                    command,
                                                    pageTime
                                            );
                                        } else if (userLogin.tooManyFailsOTP()) {
                                            long failTime = userLogin.getFailTimeOTP();
                                            int pageTime = (int) (failTime / 1000) + 1;
                                            String tempoPunicao = getTempoPunicao(failTime);
                                            String title;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                title = "Login do SPFBL";
                                            } else {
                                                title = "SPFBL Login";
                                            }
                                            String text;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                text = "Conta temporariamente bloqueada por excesso de logins fracassados.\n"
                                                        + "Aguarde cerca de " + tempoPunicao + " para tentar novamente.";
                                            } else {
                                                text = "Account temporarily blocked due to overflow of failed logins.\n"
                                                        + "Wait for about " + tempoPunicao + " to try again.";
                                            }
                                            message = getRedirectHMTL(
                                                    locale,
                                                    title,
                                                    text,
                                                    command,
                                                    pageTime
                                            );
                                        } else {
                                            String title;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                title = "A senha inserida é inválida para esta conta";
                                            } else {
                                                title = "The password entered is invalid for this account";
                                            }
                                            String text;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                text = "Digite a senha novamente se tiver certeza que está correta:";
                                            } else {
                                                text = "Retype the password if you are sure it is correct:";
                                            }
                                            message = getLoginPasswordHMTL(locale, title, text);
                                        }
                                    } else {
                                        String title;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            title = "Página de login do SPFBL";
                                        } else {
                                            title = "SPFBL login page";
                                        }
                                        String text;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            text = "Para entrar no painel de controle, digite senha de sua conta:";
                                        } else {
                                            text = "To enter the control panel, type your account's password:";
                                        }
                                        message = getLoginPasswordHMTL(locale, title, text);
                                    }
                                } else if (userLogin.hasSecretOTP() || userLogin.hasTransitionOTP()) {
                                    if (parameterMap != null && parameterMap.containsKey("otp")) {
                                        Integer otp = (Integer) parameterMap.get("otp");
                                        if (userLogin.isValidOTP(otp)) {
                                            setUser(exchange, userLogin);
                                            locale = userLogin.getLocale();
                                            message = getRedirectHTML(locale, command);
                                        } else if (userLogin.tooManyFailsOTP()) {
                                            long failTime = userLogin.getFailTimeOTP();
                                            int pageTime = (int) (failTime / 1000) + 1;
                                            String tempoPunicao = getTempoPunicao(failTime);
                                            String title;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                title = "Login do SPFBL";
                                            } else {
                                                title = "SPFBL Login";
                                            }
                                            String text;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                text = "Conta temporariamente bloqueada por excesso de logins fracassados.\n"
                                                        + "Aguarde cerca de " + tempoPunicao + " para tentar novamente.";
                                            } else {
                                                text = "Account temporarily blocked due to overflow of failed logins.\n"
                                                        + "Wait for about " + tempoPunicao + " to try again.";
                                            }
                                            message = getRedirectHMTL(
                                                    locale,
                                                    title,
                                                    text,
                                                    command,
                                                    pageTime
                                            );
                                        } else if (userLogin.hasPassword()) {
                                            String title;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                title = "Página de login do SPFBL";
                                            } else {
                                                title = "SPFBL login page";
                                            }
                                            String text;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                text = "Para entrar no painel de controle, digite a senha de sua conta:";
                                            } else {
                                                text = "To enter the control panel, type your account's password:";
                                            }
                                            message = getLoginPasswordHMTL(locale, title, text);
                                        } else if (userLogin.hasTransitionOTP()) {
                                            String title;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                title = "Página de login do SPFBL";
                                            } else {
                                                title = "SPFBL login page";
                                            }
                                            if (userLogin.hasSecretOTP()) {
                                                String text;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    text = "Para confirmar a mudança de senha "
                                                            + "<a target=\"_blank\" href=\"http://spfbl.net/totp/\">TOTP</a>, "
                                                            + "digite o valor da nova chave enviada por e-mail:";
                                                } else {
                                                    text = "To confirm the "
                                                            + "<a target=\"_blank\" href=\"http://spfbl.net/en/totp/\">TOTP</a> password change, "
                                                            + "enter the value of the new key sent by email:";
                                                }
                                                message = getLoginOTPHMTL(locale, title, text);
                                            } else {
                                                String text;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    text = "Para ativar a senha "
                                                            + "<a target=\"_blank\" href=\"http://spfbl.net/totp/\">TOTP</a> "
                                                            + "da sua conta, digite o valor da chave enviada por e-mail:";
                                                } else {
                                                    text = "To enable your account's "
                                                            + "<a target=\"_blank\" href=\"http://spfbl.net/en/totp/\">TOTP</a> "
                                                            + "password, enter the key value sent by email:";
                                                }
                                                message = getLoginOTPHMTL(locale, title, text);
                                            }
                                        } else {
                                            String title;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                title = "A senha <a target=\"_blank\" href=\"http://spfbl.net/totp/\">TOTP</a> "
                                                        + "inserida é inválida para esta conta";
                                            } else {
                                                title = "The <a target=\"_blank\" href=\"http://spfbl.net/en/totp/\">TOTP</a> password "
                                                        + "entered is invalid for this account";
                                            }
                                            String text;
                                            if (enviarOTP(locale, userLogin)) {
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    text = "Se você tiver perdido seu segredo "
                                                            + "<a target=\"_blank\" href=\"http://spfbl.net/totp/\">TOTP</a>, "
                                                            + "digite a senha do novo segredo enviado por e-mail agora mesmo:";
                                                } else {
                                                    text = "If you have lost your secret "
                                                            + "<a target=\"_blank\" href=\"http://spfbl.net/en/totp/\">TOTP</a>, "
                                                            + "enter password for new emailed secret right now:";
                                                }
                                            } else {
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    text = "Para ativar a autenticação "
                                                            + "<a target=\"_blank\" href=\"http://spfbl.net/totp/\">TOTP</a> "
                                                            + "da sua conta, digite novamente a senha:";
                                                } else {
                                                    text = "To enable "
                                                            + "<a target=\"_blank\" href=\"http://spfbl.net/en/totp/\">TOTP</a> authentication "
                                                            + "of your account, enter the password again:";
                                                }
                                            }
                                            message = getLoginOTPHMTL(locale, title, text);
                                        }
                                    } else {
                                        String title;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            title = "Página de login do SPFBL";
                                        } else {
                                            title = "SPFBL login page";
                                        }
                                        String text;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            text = "Para entrar no painel de controle, digite o valor da chave "
                                                    + "<a target=\"_blank\" href=\"http://spfbl.net/totp/\">TOTP</a> "
                                                    + "de sua conta:";
                                        } else {
                                            text = "To enter the control panel, type the "
                                                    + "<a target=\"_blank\" href=\"http://spfbl.net/en/totp/\">TOTP</a> password "
                                                    + "of your account:";
                                        }
                                        message = getLoginOTPHMTL(locale, title, text);
                                    }
                                } else {
                                    Boolean valid = validCaptcha(parameterMap);
                                    if (valid == null) {
                                        String title;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            title = "Login do SPFBL";
                                        } else {
                                            title = "SPFBL Login";
                                        }
                                        String text;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            text = "Houve uma falha ao tentar validar o reCAPTCHA. "
                                                    + "Tente novamente mais tarde.";
                                        } else {
                                            text = "There was a failure while trying to validate reCAPTCHA. "
                                                    + "Try again later.";
                                        }
                                        message = getMessageHMTL(locale, title, text);
                                    } else if (valid) {
                                        if (enviarOTP(locale, userLogin)) {
                                            String title;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                title = "Segredo "
                                                        + "<a target=\"_blank\" href=\"http://spfbl.net/totp/\">TOTP</a> "
                                                        + "enviado com sucesso";
                                            } else {
                                                title = "<a target=\"_blank\" href=\"http://spfbl.net/en/totp/\">TOTP</a> "
                                                        + "secret successfully sent";
                                            }
                                            String text;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                text = "Para confirmar a mudança de senha "
                                                        + "<a target=\"_blank\" href=\"http://spfbl.net/totp/\">TOTP</a>, "
                                                        + "digite o valor do segredo enviado por e-mail:";
                                            } else {
                                                text = "To confirm the change of password "
                                                        + "<a target=\"_blank\" href=\"http://spfbl.net/en/totp/\">TOTP</a>, "
                                                        + "enter the value of the secret sent by email:";
                                            }
                                            message = getLoginOTPHMTL(locale, title, text);
                                        } else {
                                            String title;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                title = "Login do SPFBL";
                                            } else {
                                                title = "SPFBL Login";
                                            }
                                            String text;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                text = "Não foi possível enviar o segredo "
                                                        + "<a target=\"_blank\" href=\"http://spfbl.net/totp/\">TOTP</a>.";
                                            } else {
                                                text = "Could not send "
                                                        + "<a target=\"_blank\" href=\"http://spfbl.net/en/totp/\">TOTP</a> "
                                                        + "secret";
                                            }
                                            message = getMessageHMTL(locale, title, text);
                                        }
                                    } else {
                                        String title;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            title = "Seu e-mail ainda não possui senha "
                                                    + "<a target=\"_blank\" href=\"http://spfbl.net/totp/\">TOTP</a> "
                                                    + "neste sistema";
                                        } else {
                                            title = "Your email does not have a "
                                                    + "<a target=\"_blank\" href=\"http://spfbl.net/en/totp/\">TOTP</a> "
                                                    + "password in this system";
                                        }
                                        String text;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            text = "Para receber o segredo "
                                                    + "<a target=\"_blank\" href=\"http://spfbl.net/totp/\">TOTP</a> "
                                                    + "em seu e-mail, resolva o reCAPTCHA abaixo.";
                                        } else {
                                            text = "To receive the "
                                                    + "<a target=\"_blank\" href=\"http://spfbl.net/en/totp/\">TOTP</a> "
                                                    + "secret in your email, resolve the reCAPTCHA below.";
                                        }
                                        message = getSendOTPHMTL(locale, title, text);
                                    }
                                }
                                type = "text/html";
                                tag = "PANEL";
                                code = 200;
                                result = message;
                            } else if (Core.isLong(command.substring(1))) {
                                User userLogin = getUser(exchange, SECURED);
                                if (userLogin == null) {
                                    type = "text/plain";
                                    tag = "QUERY";
                                    code = 403;
                                    result = "User not logged\n";
                                } else {
                                    long timeKey = Long.parseLong(command.substring(1));
                                    if (timeKey == 0) {
                                        type = "text/html";
                                        tag = "QUERY";
                                        code = 200;
                                        result = "";
                                    } else {
                                        User.Query query = userLogin.getQuerySafe(timeKey);
                                        if (query == null) {
                                            type = "text/plain";
                                            tag = "QUERY";
                                            code = 403;
                                            result = "";
                                        } else {
                                            type = "text/html";
                                            tag = "QUERY";
                                            code = 200;
                                            if (parameterMap != null && parameterMap.containsKey("POLICY")) {
                                                boolean holding = query.isResult("HOLD");
                                                String policy = (String) parameterMap.get("POLICY");
                                                if (policy.equals("WHITE_KEY")) {
                                                    query.clearBlock(timeKey);
                                                    query.whiteKey(timeKey);
                                                    query.processComplainForWhite();
                                                } else if (policy.equals("BLOCK_KEY")) {
                                                    query.clearWhite(timeKey);
                                                    query.blockKey(timeKey, "COMPLAIN");
                                                    query.processComplainForBlock();
                                                } else if (policy.startsWith("WHITE_")) {
                                                    query.white(timeKey, policy.substring(6));
                                                    query.processComplainForWhite();
                                                } else if (policy.startsWith("BLOCK_")) {
                                                    query.block(timeKey, policy.substring(6));
                                                    query.processComplainForBlock();
                                                }
                                                if (holding) {
                                                    query.adviseMailerDaemonHOLDING(timeKey);
                                                    User.storeDB(timeKey, query);
                                                    query.getUser().adviseMailerDaemonHOLDING();
                                                }
                                            }
                                            result = getControlPanel(locale, timeZone, query, timeKey);
                                        }
                                    }
                                }
                            } else if (isValidDomainOrIP(command.substring(1).trim())) {
                                String title;
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    title = "Página de checagem DNSBL";
                                } else {
                                    title = "DNSBL check page";
                                }
                                String token = command.substring(1).trim();
                                if (isValidIP(token)) {
                                    String ip = Subnet.normalizeIP(token);
                                    if (parameterMap != null && parameterMap.containsKey("token") && parameterMap.containsKey("PayerID") && Core.hasPayPalAccount()) {
                                        type = "text/html";
                                        tag = "DNSBL";
                                        code = 200;
                                        String paypal_user = Core.getPayPalAccountUser();
                                        String paypal_password = Core.getPayPalAccountPassword();
                                        String paypal_signature = Core.getPayPalAccountSignature();
                                        String paypal_token = (String) parameterMap.get("token");
                                        String paypal_playerid = (String) parameterMap.get("PayerID");
                                        URL url = new URL("https://api-3t.paypal.com/nvp");
                                        HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
                                        con.setConnectTimeout(3000);
                                        con.setReadTimeout(30000);
                                        con.setRequestMethod("POST");
                                        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
                                        String postParams = "USER=" + paypal_user
                                                + "&PWD=" + paypal_password
                                                + "&SIGNATURE=" + paypal_signature
                                                + "&VERSION=114.0"
                                                + "&METHOD=GetExpressCheckoutDetails"
                                                + "&TOKEN=" + paypal_token
                                                + "";
                                        con.setDoOutput(true);
                                        try (DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {
                                            wr.write(postParams.getBytes("UTF-8"));
                                            wr.flush();
                                        }
                                        StringBuilder response;
                                        try (BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
                                            String inputLine;
                                            response = new StringBuilder();
                                            while ((inputLine = in.readLine()) != null) {
                                                response.append(inputLine);
                                            }
                                        }
                                        String decoded = URLDecoder.decode(response.toString(), "UTF-8");
                                        Server.logTrace(postParams + " => " + decoded);
                                        Properties properties = new Properties();
                                        properties.load(new StringReader(decoded.replace("&", "\n")));
                                        if (properties.getProperty("ACK").equals("Success")) {
                                            String paypal_player_email = properties.getProperty("EMAIL");
                                            String paypal_currency = properties.getProperty("CURRENCYCODE");
                                            String paypal_price = properties.getProperty("AMT");
                                            String urlUnblock = Core.getPayPalUnblockURL(
                                                    locale, paypal_player_email, ip, paypal_token,
                                                    paypal_playerid, paypal_currency, paypal_price
                                            );
                                            if (urlUnblock == null) {
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    result = getMessageHMTL(
                                                            locale, title,
                                                            "Chave de desbloqueio não pode ser enviada "
                                                            + "devido a um erro interno."
                                                    );
                                                } else {
                                                    result = getMessageHMTL(
                                                            locale, title,
                                                            "Unblocking key can not be sent due "
                                                            + "to an internal error."
                                                    );
                                                }
                                            } else if (NoReply.isUnsubscribed(paypal_player_email)) {
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    result = getMessageHMTL(
                                                            locale, title,
                                                            "Chave de desbloqueio não pode ser enviada "
                                                            + "devido a um erro interno."
                                                    );
                                                } else {
                                                    result = getMessageHMTL(
                                                            locale, title,
                                                            "Unblocking key can not be sent due "
                                                            + "to an internal error."
                                                    );
                                                }
                                            } else {
                                                result = getDesbloqueioHTML(SECURED, locale, urlUnblock, ip, paypal_player_email);
                                            }
                                        } else {
                                            throw new Exception(postParams + " => " + decoded);
                                        }
                                    } else if (parameterMap != null && parameterMap.containsKey("identifier")) {
                                        Boolean valid = validCaptcha(parameterMap);
                                        if (valid == null) {
                                            type = "text/html";
                                            tag = "DNSBL";
                                            code = 200;
                                            String message;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                message = "Houve uma falha na validação do reCAPTCHA. "
                                                        + "Tente novamente.";
                                            } else {
                                                message = "reCAPTCHA validation failed. "
                                                        + "Try again.";
                                            }
                                            result = getDNSBLHTML(
                                                    SECURED, parameterMap, locale,
                                                    user, client, ip, message
                                            );
                                        } else if (valid) {
                                            TreeSet<String> postmaterSet = getPostmaterSet(ip);
                                            String abuseEmail = Abuse.getEmailFqdnOrIP(ip);
                                            if (abuseEmail != null) {
                                                postmaterSet.add(abuseEmail);
                                            }
                                            userEmail = user == null ? null : user.getEmail();
                                            if (userEmail != null) {
                                                postmaterSet.add(userEmail);
                                            }
                                            type = "text/html";
                                            tag = "DNSBL";
                                            code = 200;
                                            result = null;
                                            TreeSet<String> emailSet = (TreeSet<String>) parameterMap.get("identifier");
                                            for (String email : emailSet) {
                                                if (email.startsWith("PAYPAL_")) {
                                                    String paypal_currency = email.substring(7, 10);
                                                    String paypal_price;
                                                    if (paypal_currency.equals("USD")) {
                                                        paypal_price = Core.getPayPalPriceDelistUSD();
                                                    } else if (paypal_currency.equals("EUR")) {
                                                        paypal_price = Core.getPayPalPriceDelistEUR();
                                                    } else if (paypal_currency.equals("JPY")) {
                                                        paypal_price = Core.getPayPalPriceDelistJPY();
                                                    } else if (paypal_currency.equals("BRL")) {
                                                        paypal_price = Core.getPayPalPriceDelistBRL();
                                                    } else {
                                                        paypal_price = null;
                                                    }
                                                    if (paypal_price != null && email.endsWith("_" + paypal_price)) {
                                                        try {
                                                            String paypal_user = Core.getPayPalAccountUser();
                                                            String paypal_password = Core.getPayPalAccountPassword();
                                                            String paypal_signature = Core.getPayPalAccountSignature();
                                                            String paypal_url_return = (SECURED ? getSecuredURL() : getURL()) + uri.getPath().substring(1);
                                                            String paypal_url_cancel = (SECURED ? getSecuredURL() : getURL()) + uri.getPath().substring(1);
                                                            URL url = new URL("https://api-3t.paypal.com/nvp");
                                                            HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
                                                            con.setConnectTimeout(3000);
                                                            con.setReadTimeout(30000);
                                                            con.setRequestMethod("POST");
                                                            con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
                                                            String postParams = "USER=" + paypal_user
                                                                    + "&PWD=" + paypal_password
                                                                    + "&SIGNATURE=" + paypal_signature
                                                                    + "&METHOD=SetExpressCheckout"
                                                                    + "&VERSION=124.0"
                                                                    + "&RETURNURL=" + paypal_url_return
                                                                    + "&CANCELURL=" + paypal_url_cancel
                                                                    + "&NOSHIPPING=1"
                                                                    + "&PAYMENTREQUEST_0_PAYMENTACTION=Sale"
                                                                    + "&PAYMENTREQUEST_0_AMT=" + paypal_price
                                                                    + "&PAYMENTREQUEST_0_CURRENCYCODE=" + paypal_currency
                                                                    + "&PAYMENTREQUEST_0_DESC=DNSAL registration for IP " + ip
                                                                    + "";
                                                            con.setDoOutput(true);
                                                            try (DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {
                                                                wr.write(postParams.getBytes("UTF-8"));
                                                                wr.flush();
                                                            }
                                                            StringBuilder response;
                                                            try (BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
                                                                String inputLine;
                                                                response = new StringBuilder();
                                                                while ((inputLine = in.readLine()) != null) {
                                                                    response.append(inputLine);
                                                                }
                                                            }
                                                            String decoded = URLDecoder.decode(response.toString(), "UTF-8");
                                                            Server.logTrace(postParams + " => " + decoded);
                                                            Properties properties = new Properties();
                                                            properties.load(new StringReader(decoded.replace("&", "\n")));
                                                            if (properties.getProperty("ACK").equals("Success")) {
                                                                String paypal_token = properties.getProperty("TOKEN");
                                                                String urlPayPal = "https://www.paypal.com/cgi-bin/webscr?cmd=_express-checkout&token=" + paypal_token;
                                                                result = ServerHTTP.getRedirectHTML(locale, urlPayPal);
                                                                break;
                                                            } else {
                                                                Server.logError("autentication to PayPal service failed.");
                                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                    result = getMessageHMTL(
                                                                            locale, title,
                                                                            "Chave de desbloqueio não pode ser enviada "
                                                                            + "devido a um erro interno."
                                                                    );
                                                                } else {
                                                                    result = getMessageHMTL(
                                                                            locale, title,
                                                                            "Unblocking key can not be sent due "
                                                                            + "to an internal error."
                                                                    );
                                                                }
                                                                break;
                                                            }
                                                        } catch (UnknownHostException | SocketTimeoutException ex) {
                                                            Server.logError("autentication to PayPal service timeout.");
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                result = getMessageHMTL(
                                                                        locale, title,
                                                                        "Chave de desbloqueio não pode ser enviada "
                                                                        + "devido a um erro interno."
                                                                );
                                                            } else {
                                                                result = getMessageHMTL(
                                                                        locale, title,
                                                                        "Unblocking key can not be sent due "
                                                                        + "to an internal error."
                                                                );
                                                            }
                                                            break;
                                                        } catch (Exception ex) {
                                                            Server.logError(ex);
                                                        }
                                                    }
                                                } else if (postmaterSet.contains(email)) {
                                                    boolean started = false;
                                                    boolean defering = false;
                                                    if (email.startsWith("postmaster@")) {
                                                        started = Defer.containsExact(email);
                                                        defering = Defer.defer(email, 30);
                                                    }
                                                    if (started && defering) {
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            result = getMessageHMTL(
                                                                    locale, title,
                                                                    "Este endereço de e-mail foi usado "
                                                                            + "recentemente em outro processo de delist. "
                                                                            + "Aguarde alguns minutos antes de tentar novamente."
                                                            );
                                                        } else {
                                                            result = getMessageHMTL(
                                                                    locale, title,
                                                                    "This email address was recently used "
                                                                            + "in another delist process. "
                                                                            + "Wait a few minutes before trying again."
                                                            );
                                                        }
                                                    } else {
                                                        String url = Core.getDelistURL(locale, email, ip);
                                                        result = getDesbloqueioHTML(SECURED, locale, url, ip, email);
                                                    }
                                                    break;
                                                }
                                            }
                                            if (result == null) {
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    result = getMessageHMTL(
                                                            locale, title,
                                                            "Chave de desbloqueio não pode ser enviada "
                                                            + "devido a um erro interno."
                                                    );
                                                } else {
                                                    result = getMessageHMTL(
                                                            locale, title,
                                                            "Unblocking key can not be sent due "
                                                            + "to an internal error."
                                                    );
                                                }
                                            }
                                        } else {
                                            type = "text/html";
                                            tag = "DNSBL";
                                            code = 200;
                                            String message;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                message = "O desafio do reCAPTCHA não foi resolvido";
                                            } else {
                                                message = "The reCAPTCHA challenge has not been resolved";
                                            }
                                            result = getDNSBLHTML(SECURED, parameterMap, locale, user, client, ip, message);
                                        }
                                    } else {
                                        type = "text/html";
                                        tag = "DNSBL";
                                        code = 200;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "O e-mail do responsável pelo IP não foi definido";
                                        } else {
                                            message = "The e-mail of responsible IP was not set";
                                        }
                                        result = getDNSBLHTML(SECURED, parameterMap, locale, user, client, ip, message);
                                    }
                                } else if (isSignatureURL(token)) {
                                    try {
                                        index = token.lastIndexOf('.');
                                        String token2 = token.substring(0, index);
                                        String url = Core.decompressAsString(token2);
                                        type = "text/html";
                                        tag = "URIBL";
                                        code = 200;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Resultado da checagem da URL<br>" + url;
                                        } else {
                                            message = "Check the result of URL<br>" + url;
                                        }
                                        result = getDNSBLHTML(SECURED, parameterMap, locale, user, client, token, message);
                                    } catch (Exception ex) {
                                        type = "text/html";
                                        tag = "URIBL";
                                        code = 500;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "O identificador informado não é uma URL válida.";
                                        } else {
                                            message = "The reported identifier is not a valid URL.";
                                        }
                                        result = getMessageHMTL(locale, title, message);
                                    }
                                } else {
                                    type = "text/html";
                                    tag = "DNSBL";
                                    code = 500;
                                    String message;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        message = "O identificador informado não é um IP válido.";
                                    } else {
                                        message = "Informed identifier is not a valid IP domain.";
                                    }
                                    result = getMessageHMTL(locale, title, message);
                                }
                            } else {
                                try {
                                    String ticket = command.substring(1);
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
                                        if (System.currentTimeMillis() - timeKey > Server.WEEK_TIME) {
                                            String title;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                title = "Página do SPFBL";
                                            } else {
                                                title = "SPFBL page";
                                            }
                                            type = "text/html";
                                            tag = "HTTPC";
                                            code = 500;
                                            String message;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                message = "Ticket expirado.";
                                            } else {
                                                message = "Expired ticket.";
                                            }
                                            result = getMessageHMTL(locale, title, message);
                                        } else {
                                            String query = Core.decodeHuffman(byteArray, 8);
                                            StringTokenizer tokenizer = new StringTokenizer(query, " ");
                                            String operator = tokenizer.nextToken();
                                            if (operator.equals("spam")) {
                                                String ip = null;
                                                String sender = null;
                                                String helo = null;
                                                String hostname = null;
                                                String recipient = null;
                                                userEmail = null;
                                                TreeSet<String> tokenSet = new TreeSet<>();
                                                while (tokenizer.hasMoreTokens()) {
                                                    String token = tokenizer.nextToken();
                                                    if (token.startsWith(">") && isValidEmail(token.substring(1))) {
                                                        recipient = token.substring(1);
                                                    } else if (token.endsWith(":") && isValidEmail(token.substring(0, token.length() - 1))) {
                                                        userEmail = token.substring(0, token.length() - 1);
                                                    } else if (token.startsWith("@") && isHostname(token.substring(1))) {
                                                        sender = token;
                                                        tokenSet.add(token);
                                                    } else if (Domain.isMailFrom(token)) {
                                                        sender = token;
                                                        tokenSet.add(token);
                                                    } else if (isHostname(token)) {
                                                        if (hostname == null || hostname.length() < token.length()) {
                                                            hostname = token;
                                                            helo = token;
                                                        }
                                                        tokenSet.add(token);
                                                    } else if (isValidIP(token)) {
                                                        ip = token;
                                                        tokenSet.add(token);
                                                    } else {
                                                        tokenSet.add(token);
                                                    }
                                                }
                                                if (hostname == null) {
                                                    hostname = Reverse.getValidHostname(ip);
                                                }
                                                type = "text/html";
                                                tag = "HTTPC";
                                                String title;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    title = "Página de denuncia SPFBL";
                                                } else {
                                                    title = "SPFBL complaint page";
                                                }
                                                User userTicket = User.get(userEmail);
                                                Query queryTicket = userTicket == null ? null : userTicket.getQuerySafe(timeKey);
                                                if (queryTicket == null) {
                                                    if (sender == null) {
                                                        userEmail = userEmail == null ? "" : userEmail + ':';
                                                        if (parameterMap != null && parameterMap.containsKey("identifier")) {
                                                            TreeSet<String> identifierSet = (TreeSet<String>) parameterMap.get("identifier");
                                                            tokenSet = SPF.expandTokenSet(tokenSet);
                                                            Boolean valid = validCaptcha(parameterMap);
                                                            if (valid == null) {
                                                                type = "text/plain";
                                                                tag = "HTTPC";
                                                                code = 200;
                                                                String message;
                                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                    message = "Houve uma falha na validação do reCAPTCHA. "
                                                                            + "Tente novamente.";
                                                                } else {
                                                                    message = "ReCAPTCHA validation failed. "
                                                                            + "Try again.";
                                                                }
                                                                result = getComplainHMTL(locale, tokenSet, identifierSet, message, true);
                                                            } else if (valid) {
                                                                TreeSet<String> blockSet = new TreeSet<>();
                                                                for (String identifier : identifierSet) {
                                                                    if (tokenSet.contains(identifier)) {
                                                                        long time2 = System.currentTimeMillis();
                                                                        String block = userEmail + identifier + '>' + recipient;
                                                                        if (Block.addExact(block)) {
                                                                            Server.logQuery(time2, "BLOCK",
                                                                                    origin, timeKey,
                                                                                    "BLOCK ADD " + block,
                                                                                    "ADDED"
                                                                            );
                                                                        }
                                                                        blockSet.add(identifier);
                                                                    }
                                                                }
                                                                type = "text/plain";
                                                                tag = "HTTPC";
                                                                code = 200;
                                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                    result = "Bloqueados: " + blockSet + " >" + recipient + "\n";
                                                                } else {
                                                                    result = "Blocked: " + blockSet + " >" + recipient + "\n";
                                                                }
                                                            } else {
                                                                type = "text/plain";
                                                                tag = "HTTPC";
                                                                code = 200;
                                                                String message;
                                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                    message = "O desafio do reCAPTCHA não foi resolvido. Tente novamente.";
                                                                } else {
                                                                    message = "The CAPTCHA challenge has not been resolved. Try again.";
                                                                }
                                                                result = getComplainHMTL(locale, tokenSet, identifierSet, message, true);
                                                            }
                                                        } else {
                                                            type = "text/plain";
                                                            tag = "HTTPC";
                                                            code = 500;
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                result = "Identificadores indefinidos.\n";
                                                            } else {
                                                                result = "Undefined identifiers.\n";
                                                            }
                                                        }
                                                    } else {
                                                        String blockKey = Block.keyBlockKey(
                                                                userEmail, ip, helo, sender,
                                                                hostname, "PASS", recipient
                                                        );
                                                        if (Block.containsExact(blockKey)) {
                                                            code = 200;
                                                            String message;
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "Este remetente foi definitivamente bloqueado.";
                                                            } else {
                                                                message = "This sender was definitely blocked.";
                                                            }
                                                            result = getMessageHMTL(locale, title, message);
                                                        } else {
                                                            code = 200;
                                                            String message;
                                                            if (Block.addExact(blockKey)) {
                                                                White.clear(timeKey, userEmail, ip, sender, hostname, "PASS", recipient);
                                                                blockKey = Block.keyBlockKey(userEmail, ip, helo, sender, hostname, "PASS", null);
                                                                if (Reputation.isUndesirable(ip, hostname, hostname, sender, "PASS", user, recipient) && Block.addExact(blockKey)) {
                                                                    Server.logDebug(timeKey, "new BLOCK '" + blockKey + "' added by 'COMPLAIN'.");
                                                                }
                                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                    message = "Este remetente foi definitivamente bloqueado.";
                                                                } else {
                                                                    message = "This sender was definitely blocked.";
                                                                }
                                                            } else {
                                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                    message = "Este remetente está definitivamente bloqueado.";
                                                                } else {
                                                                    message = "This sender is definitely blocked.";
                                                                }
                                                            }
                                                            result = getMessageHMTL(locale, title, message);
                                                        }
                                                    }
                                                } else if (queryTicket.isBlockedForRecipient()) {
                                                    code = 200;
                                                    String message;
                                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                        message = "Este remetente foi definitivamente bloqueado.";
                                                    } else {
                                                        message = "This sender was definitely blocked.";
                                                    }
                                                    result = getMessageHMTL(locale, title, message);
                                                } else {
                                                    code = 200;
                                                    String message;
                                                    if (queryTicket.blockForRecipient(timeKey)) {
                                                        queryTicket.clearWhite(timeKey);
                                                        if (queryTicket.isHarmful()) {
                                                            queryTicket.blockKey(timeKey, "COMPLAIN");
                                                        }
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Este remetente foi definitivamente bloqueado.";
                                                        } else {
                                                            message = "This sender was definitely blocked.";
                                                        }
                                                    } else {
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Este remetente está definitivamente bloqueado.";
                                                        } else {
                                                            message = "This sender is definitely blocked.";
                                                        }
                                                    }
                                                    result = getMessageHMTL(locale, title, message);
                                                }
                                            } else if (operator.equals("unblock") || operator.equals("delist")) {
                                                String title;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    title = "Página de desbloqueio do SPFBL";
                                                } else {
                                                    title = "SPFBL unblock page";
                                                }
                                                try {
                                                    Boolean valid = validCaptcha(parameterMap);
                                                    userEmail = tokenizer.nextToken();
                                                    String ip = tokenizer.nextToken();
                                                    if (valid == null) {
                                                        type = "text/html";
                                                        tag = "BLOCK";
                                                        code = 200;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Houve uma falha na validação do reCAPTCHA. "
                                                                    + "Tente novamente.";
                                                        } else {
                                                            message = "reCAPTCHA validation failed. "
                                                                    + "Try again.";
                                                        }
                                                        result = getUnblockHMTL(locale, message);
                                                    } else if (!tokenizer.hasMoreTokens()) {
                                                        if (valid) {
                                                            String message;
                                                            if (Block.clearCIDR(null, ip, userEmail)) {
                                                                if (operator.equals("delist")) {
                                                                    String fqdn = FQDN.discoverFQDN(ip);
                                                                    if (fqdn == null && userEmail.startsWith("postmaster@")) {
                                                                        String rdns = Reverse.getValidHostname(ip);
                                                                        if (rdns != null) {
                                                                            int index2 = userEmail.indexOf('@') + 1;
                                                                            String domain = '.' + userEmail.substring(index2);
                                                                            if (rdns.endsWith(domain)) {
                                                                                Generic.clearGeneric(ip, userEmail);
                                                                                if (FQDN.addFQDN(ip, rdns, false)) {
                                                                                    fqdn = rdns;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                    Block.clearFQDN(null, fqdn, userEmail);
                                                                    if (!Abuse.containsEmailCIDR(ip, userEmail)) {
                                                                        if (fqdn == null) {
                                                                            Abuse.put(ip, userEmail);
                                                                        } else {
                                                                            Abuse.put(fqdn, userEmail);
                                                                            Abuse.dropSafe(ip);
                                                                        }
                                                                    }
                                                                }
                                                                NoReply.dropSafe(userEmail);
                                                                Trap.dropSafe(userEmail);
                                                                TreeSet<String> tokenSet = Reverse.getPointerSet(ip);
                                                                tokenSet.add(userEmail);
                                                                String block;
                                                                for (String token : tokenSet) {
                                                                    while ((block = Block.find(null, null, token, false, true, true, false)) != null) {
                                                                        if (Block.dropExact(block)) {
                                                                            Server.logDebug(timeKey, "false positive BLOCK '" + block + "' detected by '" + userEmail + "'.");
                                                                        }
                                                                    }
                                                                }
                                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                    message = "O IP " + ip + " foi desbloqueado com sucesso.";
                                                                } else {
                                                                    message = "The IP " + ip + " was successfully unblocked.";
                                                                }
                                                            } else {
                                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                    message = "O IP " + ip + " já estava delistado.";
                                                                } else {
                                                                    message = "The IP " + ip + " was already delisted.";
                                                                }
                                                            }
                                                            type = "text/html";
                                                            tag = "BLOCK";
                                                            code = 200;
                                                            result = getMessageHMTL(locale, title, message);
                                                        } else {
                                                            type = "text/html";
                                                            tag = "BLOCK";
                                                            code = 200;
                                                            String message;
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "O desafio reCAPTCHA não foi resolvido. "
                                                                        + "Tente novamente.";
                                                            } else {
                                                                message = "The reCAPTCHA challenge was not resolved. "
                                                                        + "Try again.";
                                                            }
                                                            result = getUnblockDNSBLHMTL(locale, message);
                                                        }
                                                    } else if (valid) {
                                                        User userLocal = User.get(userEmail);
                                                        String sender = tokenizer.nextToken();
                                                        String recipient = tokenizer.nextToken();
                                                        String hostname = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                                                        String userEmail2 = userEmail == null ? "" : userEmail + ':';
                                                        String mx = Domain.extractHost(sender, true);
                                                        String origem = Provider.containsExact(mx) ? sender : mx;
                                                        String white = origem + ">" + recipient;
                                                        String url = Core.getWhiteURL(locale, white, userEmail2, ip, sender, hostname, recipient);
                                                        String message;
                                                        try {
                                                            if (userLocal != null && userLocal.adviseRecipientBLOCK(sender, recipient, url)) {
                                                                white = White.normalizeTokenWhite(white);
                                                                Block.addExact(userEmail2 + white);
                                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                    message = "A solicitação de desbloqueio foi enviada "
                                                                            + "para o destinatário " + recipient + ".\n"
                                                                            + "A fim de não prejudicar sua reputação, "
                                                                            + "aguarde pelo desbloqueio sem enviar novas mensagens."
                                                                            + (NoReply.contains(sender, true) ? "" : "\n"
                                                                                    + "Você receberá uma mensagem deste sistema assim "
                                                                                    + "que o destinatário autorizar o recebimento.");
                                                                } else {
                                                                    message = "The release request was sent to the "
                                                                            + "recipient " + recipient + ".\n"
                                                                            + "In order not to damage your reputation, "
                                                                            + "wait for the release without sending new messages."
                                                                            + (NoReply.contains(sender, true) ? "" : "\n"
                                                                                    + "You will receive a message from this system "
                                                                                    + "when the recipient authorize receipt.");
                                                                }
                                                            } else if (userLocal == null && enviarDesbloqueio(userEmail, url, sender, recipient)) {
                                                                white = White.normalizeTokenWhite(white);
                                                                Block.addExact(userEmail2 + white);
                                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                    message = "A solicitação de desbloqueio foi enviada "
                                                                            + "para o destinatário " + recipient + ".\n"
                                                                            + "A fim de não prejudicar sua reputação, "
                                                                            + "aguarde pelo desbloqueio sem enviar novas mensagens."
                                                                            + (NoReply.contains(sender, true) ? "" : "\n"
                                                                                    + "Você receberá uma mensagem deste sistema assim "
                                                                                    + "que o destinatário autorizar o recebimento.");
                                                                } else {
                                                                    message = "The release request was sent to the "
                                                                            + "recipient " + recipient + ".\n"
                                                                            + "In order not to damage your reputation, "
                                                                            + "wait for the release without sending new messages."
                                                                            + (NoReply.contains(sender, true) ? "" : "\n"
                                                                                    + "You will receive a message from this system "
                                                                                    + "when the recipient authorize receipt.");
                                                                }
                                                            } else {
                                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                    message = "Não foi possível enviar a solicitação de "
                                                                            + "desbloqueio para o destinatário "
                                                                            + "" + recipient + " devido a problemas técnicos.";
                                                                } else {
                                                                    message = "Could not send the request release to the recipient "
                                                                            + "" + recipient + " due to technical problems.";
                                                                }
                                                            }
                                                        } catch (NameNotFoundException ex) {
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "A solicitação de desbloqueio não pode ser enviada "
                                                                        + "pois este domínio não existe no DNS.";
                                                            } else {
                                                                message = "The unlock request can not be sent "
                                                                        + "because this domain does not exist in DNS.";
                                                            }
                                                        } catch (SMTPAddressFailedException afex) {
                                                            if (afex.getReturnCode() == 551 || afex.getMessage().contains(" 5.1.1 ")) {
                                                                Trap.addInexistentSafe(user, recipient);
                                                            }
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "Chave de desbloqueio não pode ser enviada "
                                                                        + "porque o endereço " + recipient + " não existe.";
                                                            } else {
                                                                message = "Unlock key can not be sent because the "
                                                                        + "" + recipient + " address does not exist.";
                                                            }
                                                        } catch (SendFailedException ex) {
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "A solicitação de desbloqueio não pode ser enviada "
                                                                        + "devido a recusa do servidor de destino:\n"
                                                                        + ex.getCause().getMessage();
                                                            } else {
                                                                message = "The release request can not be sent due to "
                                                                        + "denial of destination server:\n"
                                                                        + ex.getCause().getMessage();
                                                            }
                                                        } catch (MailConnectException ex) {
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "A solicitação de desbloqueio não pode ser enviada "
                                                                        + "pois o MX de destino se encontra indisponível.";
                                                            } else {
                                                                message = "The release request can not be sent because "
                                                                        + "the destination MX is unavailable.";
                                                            }
                                                        } catch (CommunicationException ex) {
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "A solicitação de desbloqueio não pode ser enviada "
                                                                        + "pois o MX de destino não pode ser localizado.";
                                                            } else {
                                                                message = "The release request can not be sent because "
                                                                        + "the destination MX can not be located.";
                                                            }
                                                        } catch (SocketTimeoutException ex) {
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "A solicitação de desbloqueio não pode ser enviada pois "
                                                                        + "o MX de destino demorou demais para iniciar a transação SMTP.";
                                                            } else {
                                                                message = "The release request can not be sent because the destination "
                                                                        + "MX has taken too long to initiate the SMTP transaction.";
                                                            }
                                                        } catch (SocketConnectException ex) {
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "A solicitação de desbloqueio não pode ser enviada pois "
                                                                        + "o MX de destino está recusando nossa conexão.";
                                                            } else {
                                                                message = "The release request can not be sent because "
                                                                        + "the destination MX is declining our connection.";
                                                            }
                                                        } catch (MessagingException ex) {
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "A solicitação de desbloqueio não pode ser enviada pois "
                                                                        + "o MX de destino está recusando nossa mensagem.";
                                                            } else {
                                                                message = "The release request can not be sent because "
                                                                        + "the destination MX is declining our message.";
                                                            }
                                                        } catch (Exception ex) {
                                                            Server.logError(ex);
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "A solicitação de desbloqueio não pode "
                                                                        + "ser enviada por um erro inesperado.";
                                                            } else {
                                                                message = "The unlock request can not be sent "
                                                                        + "because of an unexpected error.";
                                                            }
                                                        }
                                                        type = "text/html";
                                                        tag = "BLOCK";
                                                        code = 200;
                                                        result = getMessageHMTL(locale, title, message);
                                                    } else {
                                                        type = "text/html";
                                                        tag = "BLOCK";
                                                        code = 200;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "O desafio reCAPTCHA não foi resolvido. "
                                                                    + "Tente novamente.";
                                                        } else {
                                                            message = "The reCAPTCHA challenge was not resolved. "
                                                                    + "Try again.";
                                                        }
                                                        result = getUnblockHMTL(locale, message);
                                                    }
                                                } catch (Exception ex) {
                                                    type = "text/plain";
                                                    tag = "SPFSP";
                                                    code = 500;
                                                    result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                                                }
                                            } else if (operator.equals("holding")) {
                                                String title;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    title = "Página de liberação do SPFBL";
                                                } else {
                                                    title = "SPFBL release page";
                                                }
                                                try {
                                                    Boolean valid = validCaptcha(parameterMap);
                                                    if (valid == null) {
                                                        type = "text/html";
                                                        tag = "HOLDN";
                                                        code = 200;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Houve uma falha na validação do reCAPTCHA. "
                                                                    + "Tente novamente.";
                                                        } else {
                                                            message = "reCAPTCHA validation failed. "
                                                                    + "Try again.";
                                                        }
                                                        result = getRequestHoldHMTL(locale, message);
                                                    } else if (valid) {
                                                        String email = tokenizer.nextToken();
                                                        User userLocal = User.get(email);
                                                        Query queryLocal = userLocal == null ? null : userLocal.getQuerySafe(timeKey);
                                                        if (queryLocal == null) {
                                                            type = "text/html";
                                                            tag = "HOLDN";
                                                            code = 500;
                                                            String message;
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "Este ticket de liberação não existe mais.";
                                                            } else {
                                                                message = "This release ticket does not exist any more.";
                                                            }
                                                            result = getMessageHMTL(locale, title, message);
                                                        } else if (queryLocal.isResult("WHITE")) {
                                                            type = "text/html";
                                                            tag = "HOLDN";
                                                            code = 200;
                                                            String message;
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "Esta mensagem já foi entregue.";
                                                            } else {
                                                                message = "This message has already been delivered.";
                                                            }
                                                            result = getMessageHMTL(locale, title, message);
                                                        } else if (queryLocal.isWhiteKey()) {
                                                            type = "text/html";
                                                            tag = "HOLDN";
                                                            code = 200;
                                                            String message;
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "Esta mensagem já foi liberada.";
                                                            } else {
                                                                message = "This message has already been released.";
                                                            }
                                                            result = getMessageHMTL(locale, title, message);
                                                        } else if (queryLocal.isBlockKey()) {
                                                            type = "text/html";
                                                            tag = "HOLDN";
                                                            code = 200;
                                                            String message;
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "Esta mensagem foi definitivamente bloqueada.";
                                                            } else {
                                                                message = "This message has been permanently blocked.";
                                                            }
                                                            result = getMessageHMTL(locale, title, message);
                                                        } else if (queryLocal.isRecipientAdvised()) {
                                                            type = "text/html";
                                                            tag = "HOLDN";
                                                            code = 200;
                                                            String message;
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "O destinatário ainda não decidiu pela liberação desta mensagem.";
                                                            } else {
                                                                message = "The recipient has not yet decided to release this message.";
                                                            }
                                                            result = getMessageHMTL(locale, title, message);
                                                        } else if (queryLocal.requestReleaseToRecipient(timeKey)) {
                                                            type = "text/html";
                                                            tag = "HOLDN";
                                                            code = 200;
                                                            String message;
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "Solicitação foi enviada com sucesso.";
                                                            } else {
                                                                message = "Request was sent successfully.";
                                                            }
                                                            result = getMessageHMTL(locale, title, message);
                                                        } else {
                                                            type = "text/html";
                                                            tag = "HOLDN";
                                                            code = 500;
                                                            String message;
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "A solicitação não pode mais ser enviada.";
                                                            } else {
                                                                message = "The request can no longer be sent.";
                                                            }
                                                            result = getMessageHMTL(locale, title, message);
                                                        }
                                                    } else {
                                                        type = "text/html";
                                                        tag = "HOLDN";
                                                        code = 200;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "O desafio reCAPTCHA não foi "
                                                                    + "resolvido. Tente novamente.";
                                                        } else {
                                                            message = "The reCAPTCHA challenge "
                                                                    + "was not resolved. Try again.";
                                                        }
                                                        result = getRequestHoldHMTL(locale, message);
                                                    }
                                                } catch (Exception ex) {
                                                    type = "text/plain";
                                                    tag = "HOLDN";
                                                    code = 500;
                                                    result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                                                }
                                            } else if (operator.equals("unholdadmin")) {
                                                String title;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    title = "Página de liberação do SPFBL";
                                                } else {
                                                    title = "SPFBL release page";
                                                }
                                                try {
                                                    String email = tokenizer.nextToken();
                                                    String blockKey = tokenizer.nextToken();
                                                    blockKey = blockKey.replace('+', '=').toUpperCase();
                                                    blockKey = new String(Core.BASE32STANDARD.decode(blockKey));
                                                    TreeMap<Long,Query> querieMap = User.getQueries(email, timeKey, blockKey);
                                                    if (querieMap == null) {
                                                        type = "text/html";
                                                        tag = "UHOLD";
                                                        code = 500;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Este ticket de liberação não existe mais.";
                                                        } else {
                                                            message = "This release ticket does not exist any more.";
                                                        }
                                                        result = getMessageHMTL(locale, title, message);
                                                    } else if (querieMap.isEmpty()) {
                                                        type = "text/html";
                                                        tag = "UHOLD";
                                                        code = 200;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Estas mensagens já foram entregues.";
                                                        } else {
                                                            message = "These messages has already been delivered.";
                                                        }
                                                        result = getMessageHMTL(locale, title, message);
                                                    } else {
                                                        for (long timeKey2 : querieMap.keySet()) {
                                                            Query queryLocal = querieMap.get(timeKey2);
                                                            String whiteKey = queryLocal.getWhiteKey();
                                                            White.addExact(Core.getAdminEmail(), whiteKey);
                                                            queryLocal.adviseMailerDaemonHOLDING(timeKey2);
                                                            User.storeDB(timeKey2, queryLocal);
                                                        }
                                                        type = "text/html";
                                                        tag = "UHOLD";
                                                        code = 200;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "As mensagens foram liberadas com sucesso e serão entregues em breve.";
                                                        } else {
                                                            message = "The messages has been successfully released and will be delivered shortly.";
                                                        }
                                                        result = getMessageHMTL(locale, title, message);
                                                    }
                                                } catch (Exception ex) {
                                                    type = "text/plain";
                                                    tag = "UHOLD";
                                                    code = 500;
                                                    result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                                                }
                                            } else if (operator.equals("unhold")) {
                                                String title;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    title = "Página de liberação do SPFBL";
                                                } else {
                                                    title = "SPFBL release page";
                                                }
                                                try {
                                                    String email = tokenizer.nextToken();
                                                    Query queryLocal;
                                                    if (Core.isAdminEmail(email)) {
                                                        queryLocal = User.getAnyQuery(timeKey);
                                                    } else {
                                                        User userLocal = User.get(email);
                                                        queryLocal = userLocal == null ? null : userLocal.getQuerySafe(timeKey);
                                                    }
                                                    if (queryLocal == null) {
                                                        type = "text/html";
                                                        tag = "UHOLD";
                                                        code = 500;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Este ticket de liberação não existe mais.";
                                                        } else {
                                                            message = "This release ticket does not exist any more.";
                                                        }
                                                        result = getMessageHMTL(locale, title, message);
                                                    } else if (Core.isAdminEmail(email)) {
                                                        String whiteKey = queryLocal.getWhiteKey();
                                                        if (White.addExact(email, whiteKey)) {
                                                            queryLocal.adviseMailerDaemonHOLDING(timeKey);
                                                            User.storeDB(timeKey, queryLocal);
                                                            queryLocal.getUser().adviseMailerDaemonHOLDING();
                                                            type = "text/html";
                                                            tag = "UHOLD";
                                                            code = 200;
                                                            String message;
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "Esta mensagem foi liberada e será entregue em breve.";
                                                            } else {
                                                                message = "This message has released and will be delivered shortly.";
                                                            }
                                                            result = getMessageHMTL(locale, title, message);
                                                        } else {
                                                            type = "text/html";
                                                            tag = "UHOLD";
                                                            code = 200;
                                                            String message;
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "Esta mensagem já foi liberada antes.";
                                                            } else {
                                                                message = "This message has already been released.";
                                                            }
                                                            result = getMessageHMTL(locale, title, message);
                                                        }
                                                    } else if (queryLocal.isDelivered()) {
                                                        type = "text/html";
                                                        tag = "UHOLD";
                                                        code = 200;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Esta mensagem já foi entregue.";
                                                        } else {
                                                            message = "This message has already been delivered.";
                                                        }
                                                        result = getMessageHMTL(locale, title, message);
                                                    } else if (!queryLocal.isHolding()) {
                                                        type = "text/html";
                                                        tag = "UHOLD";
                                                        code = 200;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Esta mensagem foi descartada antes que pudesse ser liberada.";
                                                        } else {
                                                            message = "This message was discarded before it could be released.";
                                                        }
                                                        result = getMessageHMTL(locale, title, message);
                                                    } else if (queryLocal.isWhiteKey()) {
                                                        type = "text/html";
                                                        tag = "UHOLD";
                                                        code = 200;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Esta mensagem já foi liberada e será entregue em breve.";
                                                        } else {
                                                            message = "This message has already been released and will be delivered shortly.";
                                                        }
                                                        result = getMessageHMTL(locale, title, message);
                                                    } else if (queryLocal.whiteKey(timeKey)) {
                                                        queryLocal.adviseMailerDaemonHOLDING(timeKey);
                                                        User.storeDB(timeKey, queryLocal);
                                                        type = "text/html";
                                                        tag = "UHOLD";
                                                        code = 200;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "A mensagem foi liberada com sucesso e será entregue em breve.";
                                                        } else {
                                                            message = "The message has been successfully released and will be delivered shortly.";
                                                        }
                                                        result = getMessageHMTL(locale, title, message);
                                                    } else {
                                                        type = "text/html";
                                                        tag = "UHOLD";
                                                        code = 500;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "A liberação não pode ser efetivada por falha de sistema.";
                                                        } else {
                                                            message = "The release can not be effected due to system failure.";
                                                        }
                                                        result = getMessageHMTL(locale, title, message);
                                                    }
                                                } catch (Exception ex) {
                                                    type = "text/plain";
                                                    tag = "UHOLD";
                                                    code = 500;
                                                    result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                                                }
                                            } else if (operator.equals("block") || operator.equals("ban") || operator.equals("bansubject")) {
                                                String title;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    title = "Página de bloqueio do SPFBL";
                                                } else {
                                                    title = "SPFBL block page";
                                                }
                                                try {
                                                    String email = tokenizer.nextToken();
                                                    Query queryLocal;
                                                    if (Core.isAdminEmail(email)) {
                                                        queryLocal = User.getAnyQuery(timeKey);
                                                    } else {
                                                        User userLocal = User.get(email);
                                                        queryLocal = userLocal == null ? null : userLocal.getQuerySafe(timeKey);
                                                    }
                                                    if (queryLocal == null) {
                                                        type = "text/html";
                                                        tag = "BLOCK";
                                                        code = 500;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Este ticket de bloqueio não existe mais.";
                                                        } else {
                                                            message = "This block ticket does not exist any more.";
                                                        }
                                                        result = getMessageHMTL(locale, title, message);
                                                    } else if (Core.isAdminEmail(email)) {
                                                        String blockKey = queryLocal.getBlockKey();
                                                        if (Block.addExact(email, blockKey)) {
                                                            if (operator.equals("ban")) {
                                                                queryLocal.banOrBlockForAdmin(timeKey, "ADMIN");
                                                            } else if (operator.equals("bansubject")) {
                                                                queryLocal.banOrBlockForAdmin(timeKey, "ADMIN");
                                                                TreeSet<String> subjectSet = new TreeSet<>();
                                                                TreeMap<Long,Query> queryMap = User.getQueries(email, timeKey, blockKey);
                                                                for (long timeKey2 : queryMap.keySet()) {
                                                                    Query queryLocal2 = queryMap.get(timeKey2);
                                                                    if (queryLocal2 != null) {
                                                                        queryLocal2.banOrBlockForAdmin(timeKey, "ADMIN");
                                                                        String subject = queryLocal2.getSubjectWordSet(2);
                                                                        if (subject != null && subject.length() > 8) {
                                                                            subjectSet.add(subject);
                                                                        }
                                                                    }
                                                                }
                                                                queryMap = User.getQueriesSubjectWordSetHOLD(subjectSet);
                                                                for (long timeKey2 : queryMap.keySet()) {
                                                                    Query queryLocal2 = queryMap.get(timeKey2);
                                                                    if (queryLocal2 != null) {
                                                                        queryLocal2.banOrBlockForAdmin(timeKey2, "ADMIN");
                                                                        blockKey = queryLocal2.getBlockKey();
                                                                        Block.addExact(email, blockKey);
                                                                    }
                                                                }
                                                            }
                                                            type = "text/html";
                                                            tag = "BLOCK";
                                                            code = 200;
                                                            String message;
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "A mensagem foi bloqueada com sucesso e será descartada em breve.";
                                                            } else {
                                                                message = "The message has been successfully blocked and will be discarded soon.";
                                                            }
                                                            result = getMessageHMTL(locale, title, message);
                                                        } else {
                                                            type = "text/html";
                                                            tag = "BLOCK";
                                                            code = 200;
                                                            String message;
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "Esta mensagem já foi bloqueada e será descartada em breve.";
                                                            } else {
                                                                message = "This message has already been blocked and will be discarded soon.";
                                                            }
                                                            result = getMessageHMTL(locale, title, message);
                                                        }
                                                    } else if (queryLocal.isResult("ACCEPT") && queryLocal.isWhiteKey()) {
                                                        type = "text/html";
                                                        tag = "BLOCK";
                                                        code = 200;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Esta remetente foi liberado por outro usuário.";
                                                        } else {
                                                            message = "This sender has been released by another user.";
                                                        }
                                                        result = getMessageHMTL(locale, title, message);
                                                    } else if (queryLocal.isResult("ACCEPT") && queryLocal.isBlockKey()) {
                                                        type = "text/html";
                                                        tag = "BLOCK";
                                                        code = 200;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Esta remetente já foi bloqueado.";
                                                        } else {
                                                            message = "This message has already been discarded.";
                                                        }
                                                        result = getMessageHMTL(locale, title, message);
                                                    } else if (queryLocal.isResult("ACCEPT") && queryLocal.blockKey(timeKey, "COMPLAIN")) {
                                                        if (operator.equals("ban")) {
                                                            queryLocal.banOrBlock(timeKey, "COMPLAIN");
                                                        }
                                                        type = "text/html";
                                                        tag = "BLOCK";
                                                        code = 200;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "O remetente foi bloqueado com sucesso.";
                                                        } else {
                                                            message = "The sender was successfully blocked.";
                                                        }
                                                        result = getMessageHMTL(locale, title, message);
                                                    } else if (queryLocal.isResult("BLOCK") || queryLocal.isResult("REJECT")) {
                                                        type = "text/html";
                                                        tag = "BLOCK";
                                                        code = 200;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Esta mensagem já foi descartada.";
                                                        } else {
                                                            message = "This message has already been discarded.";
                                                        }
                                                        result = getMessageHMTL(locale, title, message);
                                                    } else if (queryLocal.isWhiteKey()) {
                                                        type = "text/html";
                                                        tag = "BLOCK";
                                                        code = 200;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Esta mensagem foi liberada por outro usuário.";
                                                        } else {
                                                            message = "This message has been released by another user.";
                                                        }
                                                        result = getMessageHMTL(locale, title, message);
                                                    } else if (queryLocal.isBlockKey()) {
                                                        type = "text/html";
                                                        tag = "BLOCK";
                                                        code = 200;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Esta mensagem já foi bloqueada e será descartada em breve.";
                                                        } else {
                                                            message = "This message has already been blocked and will be discarded soon.";
                                                        }
                                                        result = getMessageHMTL(locale, title, message);
                                                    } else if (queryLocal.blockKey(timeKey, "COMPLAIN")) {
                                                        if (operator.equals("ban")) {
                                                            queryLocal.banOrBlock(timeKey, "COMPLAIN");
                                                        }
                                                        queryLocal.adviseMailerDaemonHOLDING(timeKey);
                                                        User.storeDB(timeKey, queryLocal);
                                                        type = "text/html";
                                                        tag = "BLOCK";
                                                        code = 200;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "A mensagem foi bloqueada com sucesso e será descartada em breve.";
                                                        } else {
                                                            message = "The message has been successfully blocked and will be discarded soon.";
                                                        }
                                                        result = getMessageHMTL(locale, title, message);
                                                    } else {
                                                        type = "text/html";
                                                        tag = "BLOCK";
                                                        code = 500;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "O bloqueio não pode ser efetivado por falha de sistema.";
                                                        } else {
                                                            message = "The block can not be effected due to system failure.";
                                                        }
                                                        result = getMessageHMTL(locale, title, message);
                                                    }
                                                } catch (Exception ex) {
                                                    type = "text/plain";
                                                    tag = "BLOCK";
                                                    code = 500;
                                                    result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                                                }
                                            } else if (operator.equals("unsubscribe")) {
                                                String title;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    title = "Página de cancelamento do SPFBL";
                                                } else {
                                                    title = "SPFBL unsubscribe page";
                                                }
                                                try {
                                                    Boolean valid = validCaptcha(parameterMap);
                                                    if (valid == null) {
                                                        type = "text/html";
                                                        tag = "CANCE";
                                                        code = 200;
                                                        String message;
                                                        String text;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Cancelamento de alertas do SPFBL";
                                                            text = "Houve uma falha na validação do reCAPTCHA. "
                                                                    + "Tente novamente.";
                                                        } else {
                                                            message = "Unsubscribing SPFBL alerts.";
                                                            text = "reCAPTCHA validation failed. "
                                                                    + "Try again.";
                                                        }
                                                        result = getUnsubscribeHMTL(locale, message, text);
                                                    } else if (valid) {
                                                        String email = tokenizer.nextToken();
                                                        if (NoReply.addSafe(email)) {
                                                            type = "text/html";
                                                            tag = "CANCE";
                                                            code = 200;
                                                            String message;
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "O envio de alertas foi cancelado para " + email + " com sucesso.";
                                                            } else {
                                                                message = "Alert sending has been canceled for " + email + " successfully.";
                                                            }
                                                            result = getMessageHMTL(locale, title, message);
                                                        } else {
                                                            type = "text/html";
                                                            tag = "CANCE";
                                                            code = 500;
                                                            String message;
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "O sistema de alerta já estava cancelado para " + email + ".";
                                                            } else {
                                                                message = "The warning system was already unsubscribed for " + email + ".";
                                                            }
                                                            result = getMessageHMTL(locale, title, message);
                                                        }
                                                    } else {
                                                        type = "text/html";
                                                        tag = "CANCE";
                                                        code = 200;
                                                        String message;
                                                        String text;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Cancelamento de alertas do SPFBL";
                                                            text = "O desafio reCAPTCHA não foi resolvido. Tente novamente.";
                                                        } else {
                                                            message = "Unsubscribing SPFBL alerts.";
                                                            text = "The reCAPTCHA challenge was not resolved. Try again.";
                                                        }
                                                        result = getUnsubscribeHMTL(locale, message, text);
                                                    }
                                                } catch (Exception ex) {
                                                    type = "text/plain";
                                                    tag = "CANCE";
                                                    code = 500;
                                                    result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                                                }
                                            } else if (operator.equals("release")) {
                                                String title;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    title = "Página de liberação do SPFBL";
                                                } else {
                                                    title = "SPFBL release page";
                                                }
                                                try {
                                                    Boolean valid = validCaptcha(parameterMap);
                                                    if (valid == null) {
                                                        type = "text/html";
                                                        tag = "DEFER";
                                                        code = 200;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Houve uma falha na validação do reCAPTCHA. "
                                                                    + "Tente novamente.";
                                                        } else {
                                                            message = "reCAPTCHA validation failed. "
                                                                    + "Try again.";
                                                        }
                                                        result = getReleaseHMTL(locale, message);
                                                    } else if (valid) {
                                                        String id = tokenizer.nextToken();
                                                        String message;
                                                        if (Defer.release(id)) {
                                                            String clientTicket = SPF.getClient(ticket);
                                                            String sender = SPF.getSender(ticket);
                                                            String recipient = SPF.getRecipient(ticket);
                                                            if (clientTicket != null && sender != null && recipient != null) {
                                                                if (White.addExact(clientTicket + ":" + sender + ";PASS>" + recipient)) {
                                                                    Server.logDebug(timeKey, "WHITE ADD " + clientTicket + ":" + sender + ";PASS>" + recipient);
                                                                }
                                                            }
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "Sua mensagem foi liberada com sucesso.";
                                                            } else {
                                                                message = "Your message has been successfully released.";
                                                            }
                                                        } else {
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "Sua mensagem já havia sido liberada.";
                                                            } else {
                                                                message = "Your message had already been released.";
                                                            }
                                                        }
                                                        type = "text/html";
                                                        tag = "DEFER";
                                                        code = 200;
                                                        result = getMessageHMTL(locale, title, message);
                                                    } else {
                                                        type = "text/html";
                                                        tag = "DEFER";
                                                        code = 200;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "O desafio reCAPTCHA não foi "
                                                                    + "resolvido. Tente novamente.";
                                                        } else {
                                                            message = "The reCAPTCHA challenge "
                                                                    + "was not resolved. Try again.";
                                                        }
                                                        result = getReleaseHMTL(locale, message);
                                                    }
                                                } catch (Exception ex) {
                                                    type = "text/plain";
                                                    tag = "SPFSP";
                                                    code = 500;
                                                    result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                                                }
                                            } else if (operator.equals("white")) {
                                                String title;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    title = "Página de desbloqueio de remetente";
                                                } else {
                                                    title = "Sender unblock page";
                                                }
                                                try {
                                                    String white = White.normalizeTokenWhite(tokenizer.nextToken());
                                                    String clientTicket = tokenizer.nextToken();
                                                    white = clientTicket + white;
                                                    userEmail = clientTicket.replace(":", "");
                                                    String ip = tokenizer.nextToken();
                                                    String sender = tokenizer.nextToken();
                                                    String recipient = tokenizer.nextToken();
                                                    String hostname = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                                                    if (sentUnblockConfirmationSMTP.containsKey(command.substring(1))) {
                                                        type = "text/html";
                                                        tag = "WHITE";
                                                        code = 200;
                                                        result = enviarConfirmacaoDesbloqueio(
                                                                SECURED, command.substring(1),
                                                                recipient, sender, locale
                                                        );
                                                    } else if (White.addExact(white)) {
                                                        Block.clear(timeKey, userEmail, ip, sender, hostname, "PASS", recipient);
                                                        type = "text/html";
                                                        tag = "WHITE";
                                                        code = 200;
                                                        result = enviarConfirmacaoDesbloqueio(
                                                                SECURED, command.substring(1),
                                                                recipient, sender, locale
                                                        );
                                                    } else {
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "O desbloqueio do remetente " + sender + " já havia sido efetuado.";
                                                        } else {
                                                            message = "The unblock of sender " + sender + " had been made.";
                                                        }
                                                        type = "text/html";
                                                        tag = "WHITE";
                                                        code = 200;
                                                        result = getMessageHMTL(locale, title, message);
                                                    }
                                                } catch (Exception ex) {
                                                    type = "text/plain";
                                                    tag = "SPFSP";
                                                    code = 500;
                                                    result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                                                }
                                            } else {
                                                type = "text/plain";
                                                tag = "HTTPC";
                                                code = 403;
                                                result = "Forbidden\n";
                                            }
                                        }
                                    } else {
                                        type = "text/plain";
                                        tag = "HTTPC";
                                        code = 403;
                                        result = "Forbidden\n";
                                    }
                                } catch (Exception ex) {
                                    type = "text/plain";
                                    tag = "HTTPC";
                                    code = 403;
                                    result = "Forbidden\n";
                                }
                            }
                        } else if (request.equals("GET")) {
                            if (command.equals("/favicon.ico")) {
                                type = "text/plain";
                                tag = "HTTPC";
                                code = 403;
                                result = "Forbidden\n";
                            } else if (command.equals("/robots.txt")) {
                                type = "text/plain";
                                tag = "HTTPC";
                                code = 403;
                                result = "Forbidden\n";
                            } else if (SECURED && command.startsWith("/.well-known/secret-key/")) {
                                type = "text/plain";
                                tag = "SECRT";
                                index = command.lastIndexOf('/') + 1;
                                String address = command.substring(index);
                                Peer peer = Peer.get(address);
                                if (peer == null) {
                                    code = 500;
                                    result = "Unknow peer.";
                                } else if (!peer.isAddress(exchange.getRemoteAddress().getAddress())) {
                                    code = 500;
                                    result = "Invalid peer address.";
                                } else if (peer.getReceiveStatus() == Peer.Receive.DROP) {
                                    code = 500;
                                    result = "Peer not allowed.";
                                } else {
                                    try {
                                        HttpsExchange httpsExchange = (HttpsExchange) exchange;
                                        SSLSession sslSession = httpsExchange.getSSLSession();
                                        if (sslSession.isValid() && sslSession.getPeerPrincipal().getName().equals("CN=" + address)) {
                                            code = 200;
                                            result = peer.newDecryptKey();
                                            if (result == null) {
                                                code = 500;
                                                result = "Fatal error.";
                                            }
                                        } else {
                                            code = 500;
                                            result = "Invalid peer authentication.";
                                        }
                                    } catch (Exception ex) {
                                        Server.logError(ex);
                                        code = 500;
                                        result = "Fatal error.";
                                    }
                                }
                            } else if (!SECURED && command.startsWith("/.well-known/acme-challenge/")) {
                                type = "text/plain";
                                tag = "ACMEC";
                                if (CHALLENGE == null) {
                                    code = 403;
                                    result = "Forbidden\n";
                                } else if (command.endsWith("/" + CHALLENGE.getToken())) {
                                    code = 200;
                                    result = CHALLENGE.getAuthorization();
                                } else {
                                    code = 403;
                                    result = "Forbidden\n";
                                }
                            } else if (!SECURED && SERVERS != null && !HOSTNAME.equals("localhost") && !Core.isExpiringCertificate(HOSTNAME)) {
                                type = "text/html";
                                tag = "REDIR";
                                code = 301;
                                String query = command.substring(1);
                                String url = Core.getURL(true, null, query);
                                exchange.getResponseHeaders().set("Location", url);
                                result = getRedirectHTML(locale, url);
                            } else if (command.equals("/")) {
                                type = "text/html";
                                tag = "MMENU";
                                code = 200;
                                String message;
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    message = "Página principal do serviço SPFBL";
                                } else {
                                    message = "This is SPFBL's main page";
                                }
                                result = getMainHTML(locale, message, remoteAddress);
                            } else if (command.equals("/history/")) {
                                JSONObject json = new JSONObject();
                                if (parameterMap == null) {
                                    json.put("result", "FAIL");
                                    json.put("information", "no parameters was provided");
                                } else {
                                    if (parameterMap.containsKey("user") && parameterMap.containsKey("password")) {
                                        if (Core.isTestingVersion()) {
                                            userEmail = (String) parameterMap.get("user");
                                            String password = (String) parameterMap.get("password");
                                            user = User.get(userEmail, password);
                                            if (user == null) {
                                                json.put("result", "INVALID");
                                                json.put("information", "invalid credential");
                                            } else {
                                                locale = user.getLocale();
                                                origin = getOrigin(remoteAddress, client, userEmail);
                                                json.put("result", "VALID");
                                                json.put("information", "valid credential");
                                                json.put("language", locale.getLanguage());
                                            }
                                        } else {
                                            json.put("result", "FAIL");
                                            json.put("information", "you cannot define the credential here for security reasons");
                                        }
                                    } else if (user == null) {
                                        json.put("result", "EXPIRED");
                                        json.put("information", "expired session");
                                    } else {
                                        json.put("result", "VALID");
                                        json.put("information", "valid credential");
                                        json.put("language", locale.getLanguage());
                                    }
                                    if (user != null) {
                                        Long begin = (Long) parameterMap.get("begin");
                                        String filter = (String) parameterMap.get("filter");
                                        TreeMap<Long,Query> queryMap = user.getQueryMap(begin, filter);
                                        if (queryMap == null) {
                                            json.put("result", "UNAVAILABLE");
                                            json.put("information", "unavailable service");
                                        } else {
                                            DateFormat dateFormat = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM, locale);
                                            dateFormat.setTimeZone(timeZone);
                                            GregorianCalendar calendar = new GregorianCalendar(locale);
                                            calendar.setTimeZone(timeZone);
                                            Long nextQuery = null;
                                            JSONArray array = new JSONArray();
                                            for (long timeKey : queryMap.descendingKeySet()) {
                                                User.Query query = queryMap.get(timeKey);
                                                if (query == null) {
                                                    nextQuery = timeKey;
                                                    break;
                                                } else {
                                                    JSONObject jsonElement = new JSONObject();
                                                    jsonElement.put("key", timeKey);
                                                    calendar.setTimeInMillis(timeKey);
                                                    jsonElement.put("arrival", Core.formatEmailDate(calendar.getTime()));
                                                    jsonElement.put("client", query.getClient());
                                                    jsonElement.put("queueid", query.getQueueID());
                                                    jsonElement.put("ip", query.getIP());
                                                    jsonElement.put("fqdn", query.getFQDN());
                                                    jsonElement.put("helo", query.getHELO());
                                                    jsonElement.put("sender", query.getSender());
                                                    jsonElement.put("qualifier", query.getQualifier());
                                                    jsonElement.put("recipient", query.getRecipient());
                                                    jsonElement.put("layer", "ENVELOPE");
                                                    if (query.hasHeaderInformation()) {
                                                        jsonElement.put("layer", "HEADER");
                                                        jsonElement.put("from", query.getFrom());
                                                        jsonElement.put("replyto", query.getReplyTo());
                                                        jsonElement.put("subject", query.getSubject());
                                                        jsonElement.put("departure", Core.formatEmailDate(query.getMessageDate(calendar)));
                                                        if (query.hasBodyInformation2()) {
                                                            jsonElement.put("layer", "BODY");
                                                            jsonElement.put("body", query.getTextPlainBody());
                                                            jsonElement.put("links", query.getLinkSet());
                                                            jsonElement.put("executable", query.getExecutableSet());
                                                            jsonElement.put("malware", query.getMalware());
                                                        }
                                                    }
                                                    jsonElement.put("abuse", query.getAbuseReported());
                                                    jsonElement.put("filter", query.getFilterEnum());
                                                    jsonElement.put("result", query.getResult());
                                                    array.add(jsonElement);
                                                }
                                            }
                                            json.put("message", array);
                                            if (nextQuery != null) {
                                                json.put("next", nextQuery);
                                            }
                                        }
                                    }
                                }
                                if (Core.isTestingVersion()) {
                                    Headers headers = exchange.getResponseHeaders();
                                    headers.set("Access-Control-Allow-Origin", "*");
                                }
                                tag = "HISTO";
                                type = "application/json";
                                code = 200;
                                result = json.toJSONString();
                            } else if (command.equals("/registry/")) {
                                JSONObject json = new JSONObject();
                                if (parameterMap == null) {
                                    json.put("result", "FAIL");
                                    json.put("information", "no parameters was provided");
                                } else {
                                    if (parameterMap.containsKey("user") && parameterMap.containsKey("password")) {
                                        if (Core.isTestingVersion()) {
                                            userEmail = (String) parameterMap.get("user");
                                            String password = (String) parameterMap.get("password");
                                            user = User.get(userEmail, password);
                                            if (user == null) {
                                                json.put("result", "INVALID");
                                                json.put("information", "invalid credential");
                                            } else {
                                                locale = user.getLocale();
                                                origin = getOrigin(remoteAddress, client, userEmail);
                                                json.put("result", "VALID");
                                                json.put("information", "valid credential");
                                                json.put("language", locale.getLanguage());
                                            }
                                        } else {
                                            json.put("result", "FAIL");
                                            json.put("information", "you cannot define the credential here for security reasons");
                                        }
                                    } else if (user == null) {
                                        json.put("result", "EXPIRED");
                                        json.put("information", "expired session");
                                    } else {
                                        json.put("result", "VALID");
                                        json.put("information", "valid credential");
                                        json.put("language", locale.getLanguage());
                                    }
                                    if (user != null) {
                                        Long timeKey = (Long) parameterMap.get("timekey");
                                        if (timeKey == null) {
                                            json.put("result", "INVALID");
                                            json.put("information", "invalid key");
                                        } else {
                                            Query query = user.getQuery(timeKey);
                                            if (query == null) {
                                                json.put("result", "NOTFOUND");
                                                json.put("information", "registry not found");
                                            } else {
                                                DateFormat dateFormat = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM, locale);
                                                dateFormat.setTimeZone(timeZone);
                                                GregorianCalendar calendar = new GregorianCalendar(locale);
                                                calendar.setTimeZone(timeZone);
                                                JSONObject jsonElement = new JSONObject();
                                                jsonElement.put("key", timeKey);
                                                calendar.setTimeInMillis(timeKey);
                                                jsonElement.put("arrival", Core.formatEmailDate(calendar.getTime()));
                                                jsonElement.put("client", query.getClient());
                                                jsonElement.put("queueid", query.getQueueID());
                                                jsonElement.put("ip", query.getIP());
                                                jsonElement.put("fqdn", query.getFQDN());
                                                jsonElement.put("helo", query.getHELO());
                                                jsonElement.put("sender", query.getSender());
                                                jsonElement.put("qualifier", query.getQualifier());
                                                jsonElement.put("recipient", query.getRecipient());
                                                jsonElement.put("simplified", query.getSenderSimplified(false, false));
                                                jsonElement.put("layer", "ENVELOPE");
                                                if (query.hasHeaderInformation()) {
                                                    jsonElement.put("layer", "HEADER");
                                                    jsonElement.put("from", query.getFrom());
                                                    jsonElement.put("replyto", query.getReplyTo());
                                                    jsonElement.put("subject", query.getSubject());
                                                    jsonElement.put("departure", Core.formatEmailDate(query.getMessageDate(calendar)));
                                                    if (query.hasBodyInformation2()) {
                                                        jsonElement.put("layer", "BODY");
                                                        jsonElement.put("body", query.getTextPlainBody());
                                                        jsonElement.put("links", query.getLinkSet());
                                                        jsonElement.put("executable", query.getExecutableSet());
                                                        jsonElement.put("malware", query.getMalware());
                                                    }
                                                }
                                                jsonElement.put("abuse", query.getAbuseReported());
                                                jsonElement.put("filter", query.getFilterEnum());
                                                jsonElement.put("result", query.getResult());
                                                if (query.isWhiteKey()) {
                                                    jsonElement.put("status", "WHITELISTED");
                                                } else if (query.isBlockKey()) {
                                                    jsonElement.put("status", "BLOCKED");
                                                } else {
                                                    jsonElement.put("status", "NONE");
                                                }
                                                json.put("message", jsonElement);
                                            }
                                        }
                                    }
                                }
                                if (Core.isTestingVersion()) {
                                    Headers headers = exchange.getResponseHeaders();
                                    headers.set("Access-Control-Allow-Origin", "*");
                                }
                                tag = "REGIS";
                                type = "application/json";
                                code = 200;
                                result = json.toJSONString();
                            } else if (command.equals("/white/")) {
                                JSONObject json = new JSONObject();
                                if (parameterMap == null) {
                                    json.put("result", "FAIL");
                                    json.put("information", "no parameters was provided");
                                } else {
                                    if (parameterMap.containsKey("user") && parameterMap.containsKey("password")) {
                                        if (Core.isTestingVersion()) {
                                            userEmail = (String) parameterMap.get("user");
                                            String password = (String) parameterMap.get("password");
                                            user = User.get(userEmail, password);
                                            if (user == null) {
                                                json.put("result", "INVALID");
                                                json.put("information", "invalid credential");
                                            } else {
                                                locale = user.getLocale();
                                                origin = getOrigin(remoteAddress, client, userEmail);
                                                json.put("result", "VALID");
                                                json.put("information", "valid credential");
                                                json.put("language", locale.getLanguage());
                                            }
                                        } else {
                                            json.put("result", "FAIL");
                                            json.put("information", "you cannot define the credential here for security reasons");
                                        }
                                    } else if (user == null) {
                                        json.put("result", "EXPIRED");
                                        json.put("information", "expired session");
                                    } else {
                                        json.put("result", "VALID");
                                        json.put("information", "valid credential");
                                        json.put("language", locale.getLanguage());
                                    }
                                    if (user != null) {
                                        Long timeKey = (Long) parameterMap.get("timekey");
                                        if (timeKey == null) {
                                            json.put("result", "INVALID");
                                            json.put("information", "invalid key");
                                        } else {
                                            Query query = user.getQuery(timeKey);
                                            if (query == null) {
                                                json.put("result", "NOTFOUND");
                                                json.put("information", "registry not found");
                                            } else {
                                                query.clearBlock(timeKey);
                                                query.whiteKey(timeKey);
                                                query.processComplainForWhite();
                                                json.put("result", "DONE");
                                                json.put("information", "sender whitelisted");
                                            }
                                        }
                                    }
                                }
                                if (Core.isTestingVersion()) {
                                    Headers headers = exchange.getResponseHeaders();
                                    headers.set("Access-Control-Allow-Origin", "*");
                                }
                                tag = "REGIS";
                                type = "application/json";
                                code = 200;
                                result = json.toJSONString();
                            } else if (command.equals("/block/")) {
                                JSONObject json = new JSONObject();
                                if (parameterMap == null) {
                                    json.put("result", "FAIL");
                                    json.put("information", "no parameters was provided");
                                } else {
                                    if (parameterMap.containsKey("user") && parameterMap.containsKey("password")) {
                                        if (Core.isTestingVersion()) {
                                            userEmail = (String) parameterMap.get("user");
                                            String password = (String) parameterMap.get("password");
                                            user = User.get(userEmail, password);
                                            if (user == null) {
                                                json.put("result", "INVALID");
                                                json.put("information", "invalid credential");
                                            } else {
                                                locale = user.getLocale();
                                                origin = getOrigin(remoteAddress, client, userEmail);
                                                json.put("result", "VALID");
                                                json.put("information", "valid credential");
                                                json.put("language", locale.getLanguage());
                                            }
                                        } else {
                                            json.put("result", "FAIL");
                                            json.put("information", "you cannot define the credential here for security reasons");
                                        }
                                    } else if (user == null) {
                                        json.put("result", "EXPIRED");
                                        json.put("information", "expired session");
                                    } else {
                                        json.put("result", "VALID");
                                        json.put("information", "valid credential");
                                        json.put("language", locale.getLanguage());
                                    }
                                    if (user != null) {
                                        Long timeKey = (Long) parameterMap.get("timekey");
                                        if (timeKey == null) {
                                            json.put("result", "INVALID");
                                            json.put("information", "invalid key");
                                        } else {
                                            Query query = user.getQuery(timeKey);
                                            if (query == null) {
                                                json.put("result", "NOTFOUND");
                                                json.put("information", "registry not found");
                                            } else {
                                                query.clearWhite(timeKey);
                                                query.blockKey(timeKey, "COMPLAIN");
                                                query.processComplainForBlock();
                                                json.put("result", "DONE");
                                                json.put("information", "sender blocked");
                                            }
                                        }
                                    }
                                }
                                if (Core.isTestingVersion()) {
                                    Headers headers = exchange.getResponseHeaders();
                                    headers.set("Access-Control-Allow-Origin", "*");
                                }
                                tag = "REGIS";
                                type = "application/json";
                                code = 200;
                                result = json.toJSONString();
                            } else if (isValidEmail(command.substring(1).trim())) {
                                String message;
                                userEmail = command.substring(1).toLowerCase().trim();
                                String password = (String) (parameterMap == null ? null : parameterMap.get("password"));
                                User userLogin = getUser(exchange, SECURED);
                                if (userLogin != null && userLogin.isEmail(userEmail)) {
                                    Long begin = (Long) (parameterMap == null ? null : parameterMap.get("begin"));
                                    String filter = (String) (parameterMap == null ? null : parameterMap.get("filter"));
                                    message = getControlPanel(locale, timeZone, userLogin, begin, filter);
                                } else if ((userLogin = User.get(userEmail, password)) != null) {
                                    setUser(exchange, userLogin);
                                    locale = userLogin.getLocale();
                                    Long begin = (Long) (parameterMap == null ? null : parameterMap.get("begin"));
                                    String filter = (String) (parameterMap == null ? null : parameterMap.get("filter"));
                                    message = getControlPanel(locale, timeZone, userLogin, begin, filter);
                                } else if ((userLogin = User.get(userEmail)) == null) {
                                    String title;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        title = "Login do SPFBL";
                                    } else {
                                        title = "SPFBL Login";
                                    }
                                    String text;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        text = "Usuário inexistente.";
                                    } else {
                                        text = "Non-existent user.";
                                    }
                                    message = getMessageHMTL(locale, title, text);
                                } else if (userLogin.tooManyFailsPassword()) {
                                    long failTime = userLogin.getFailTimePassword();
                                    int pageTime = (int) (failTime / 1000) + 1;
                                    String tempoPunicao = getTempoPunicao(failTime);
                                    String title;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        title = "Login do SPFBL";
                                    } else {
                                        title = "SPFBL Login";
                                    }
                                    String text;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        text = "Conta temporariamente bloqueada por excesso de logins fracassados.\n"
                                                + "Aguarde cerca de " + tempoPunicao + " para tentar novamente.";
                                    } else {
                                        text = "Account temporarily blocked due to overflow of failed logins.\n"
                                                + "Wait for about " + tempoPunicao + " to try again.";
                                    }
                                    message = getRedirectHMTL(
                                            locale,
                                            title,
                                            text,
                                            command,
                                            pageTime
                                    );
                                } else if (userLogin.tooManyFailsOTP()) {
                                    long failTime = userLogin.getFailTimeOTP();
                                    int pageTime = (int) (failTime / 1000) + 1;
                                    String tempoPunicao = getTempoPunicao(failTime);
                                    String title;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        title = "Login do SPFBL";
                                    } else {
                                        title = "SPFBL Login";
                                    }
                                    String text;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        text = "Conta temporariamente bloqueada por excesso de logins fracassados.\n"
                                                + "Aguarde cerca de " + tempoPunicao + " para tentar novamente.";
                                    } else {
                                        text = "Account temporarily blocked due to overflow of failed logins.\n"
                                                + "Wait for about " + tempoPunicao + " to try again.";
                                    }
                                    message = getRedirectHMTL(
                                            locale,
                                            title,
                                            text,
                                            command,
                                            pageTime
                                    );
                                } else if (userLogin.hasPassword()) {
                                    String title;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        title = "Página de login do SPFBL";
                                    } else {
                                        title = "SPFBL login page";
                                    }
                                    String text;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        text = "Para entrar no painel de controle, digite a senha de sua conta:";
                                    } else {
                                        text = "To enter the control panel, type your account's password:";
                                    }
                                    message = getLoginPasswordHMTL(locale, title, text);
                                } else if (userLogin.hasTransitionOTP()) {
                                    String title;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        title = "Página de login do SPFBL";
                                    } else {
                                        title = "SPFBL login page";
                                    }
                                    if (userLogin.hasSecretOTP()) {
                                        String text;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            text = "Para confirmar a mudança de segredo "
                                                    + "<a target=\"_blank\" href=\"http://spfbl.net/totp/\">TOTP</a>,\n"
                                                    + "digite o valor da nova chave enviada por e-mail:";
                                        } else {
                                            text = "To confirm the change of "
                                                    + "<a target=\"_blank\" href=\"http://spfbl.net/en/totp/\">TOTP</a>,\n"
                                                    + "secret enter the value of the new key sent by email:";
                                        }
                                        message = getLoginOTPHMTL(locale, title, text);
                                    } else {
                                        String text;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            text = "Para ativar a senha "
                                                    + "<a target=\"_blank\" href=\"http://spfbl.net/totp/\">TOTP</a> "
                                                    + "da sua conta, digite o valor da chave enviada por e-mail:";
                                        } else {
                                            text = "To activate your account's "
                                                    + "<a target=\"_blank\" href=\"http://spfbl.net/en/totp/\">TOTP</a> "
                                                    + "password, enter the key value sent by email:";
                                        }
                                        message = getLoginOTPHMTL(locale, title, text);
                                    }
                                } else if (userLogin.hasSecretOTP()) {
                                    String title;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        title = "Página de login do SPFBL";
                                    } else {
                                        title = "SPFBL login page";
                                    }
                                    String text;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        text = "Para entrar no painel de controle, digite o valor da chave "
                                                + "<a target=\"_blank\" href=\"http://spfbl.net/totp/\">TOTP</a> "
                                                + "de sua conta:";
                                    } else {
                                        text = "To enter the control panel, type the "
                                                + "<a target=\"_blank\" href=\"http://spfbl.net/en/totp/\">TOTP</a> password "
                                                + "of your account:";
                                    }
                                    message = getLoginOTPHMTL(locale, title, text);
                                } else {
                                    String title;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        title = "Seu e-mail ainda não possui senha "
                                                + "<a target=\"_blank\" href=\"http://spfbl.net/totp/\">TOTP</a> "
                                                + "neste sistema";
                                    } else {
                                        title = "Your email does not have a "
                                                + "<a target=\"_blank\" href=\"http://spfbl.net/en/totp/\">TOTP</a> "
                                                + "password in this system";
                                    }
                                    String text;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        text = "Para receber a chave "
                                                + "<a target=\"_blank\" href=\"http://spfbl.net/totp/\">TOTP</a> "
                                                + "em seu e-mail, resolva o reCAPTCHA abaixo.";
                                    } else {
                                        text = "To receive the "
                                                + "<a target=\"_blank\" href=\"http://spfbl.net/en/totp/\">TOTP</a> "
                                                + "key in your email, resolve the reCAPTCHA below.";
                                    }
                                    message = getSendOTPHMTL(locale, title, text);
                                }
                                type = "text/html";
                                tag = "PANEL";
                                code = 200;
                                result = message;
                            } else if (Core.isLong(command.substring(1))) {
                                User userLogin = getUser(exchange, SECURED);
                                if (userLogin == null) {
                                    type = "text/plain";
                                    tag = "QUERY";
                                    code = 403;
                                    result = "User not logged\n";
                                } else {
                                    long queryTime = Long.parseLong(command.substring(1));
                                    if (queryTime == 0) {
                                        type = "text/html";
                                        tag = "QUERY";
                                        code = 200;
                                        result = "";
                                    } else {
                                        User.Query query = userLogin.getQuerySafe(queryTime);
                                        if (query == null) {
                                            type = "text/plain";
                                            tag = "QUERY";
                                            code = 403;
                                            result = "";
                                        } else {
                                            type = "text/html";
                                            tag = "QUERY";
                                            code = 200;
                                            result = getControlPanel(locale, timeZone, query, queryTime);
                                        }
                                    }
                                }
                            } else if ((file = getWebFile(command.substring(1))) != null) {
                                tag = "FILER";
                                if (file.getName().endsWith(".png")) {
                                    type = "image/png";
                                } else if (file.getName().endsWith(".gif")) {
                                    type = "image/gif";
                                } else if (file.getName().endsWith(".css")) {
                                    type = "text/css";
                                } else if (file.getName().endsWith(".txt")) {
                                    type = "text/plain";
                                } else {
                                    type = "application/octet-stream";
                                }
                                long ifModifiedSince = 0;
                                try {
                                    Headers headers = exchange.getRequestHeaders();
                                    ifModifiedSince = Core.parseEmailDateLong(
                                            headers.getFirst("If-Modified-Since")
                                    );
                                } catch (Exception ex) {
                                    Server.logError(ex);
                                }
                                try {
                                   if (file.lastModified() > ifModifiedSince) {
                                        code = 200;
                                        Headers headers = exchange.getResponseHeaders();
                                        headers.set("Content-Type", type);
                                        headers.set("Cache-Control", "public, min-fresh=86400, max-age=604800"); // HTTP 1.1.
                                        headers.set("Last-Modified", Core.formatEmailDate(file.lastModified()));
                                        exchange.sendResponseHeaders(200, file.length());
                                        try (OutputStream outputStream = exchange.getResponseBody()) {
                                            Files.copy(file.toPath(), outputStream);
                                            result = file.getName() + " sent\n";
                                        }
                                    } else {
                                        code = 304;
                                        result = "Not Modified";
                                    }
                                } catch (IOException ex) {
                                    code = 500;
                                    result = ex.getMessage() + "\n";
//                                    Server.logError(ex);
                                } catch (Exception ex) {
                                    code = 500;
                                    result = ex.getMessage() + "\n";
                                    Server.logError(ex);
                                }
                            } else if (command.startsWith("/dnsbl/")) {
                                type = "text/html";
                                tag = "DNSBL";
                                code = 200;
                                String query = command.substring(7).trim();
                                if (isValidIP(query)) {
                                    query = Subnet.normalizeIP(query);
                                } else if (isHostname(query)) {
                                    query = Domain.normalizeHostname(query, false);
                                }
                                result = getRedirectHTML(locale, "/" + locale.getLanguage() + "/" + query);
                            } else if (isValidDomainOrIP(command.substring(1).trim())) {
                                String title;
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    title = "Página de checagem DNSBL";
                                } else {
                                    title = "DNSBL check page";
                                }
                                String query = command.substring(1).trim();
                                if (isValidIP(query)) {
                                    String ip = Subnet.normalizeIP(query);
                                    if (sentUnblockKeySMTP.containsKey(ip)) {
                                        type = "text/html";
                                        tag = "DNSBL";
                                        code = 200;
                                        String email = null;
                                        String url = null;
                                        result = getDesbloqueioHTML(SECURED, locale, url, ip, email);
                                    } else {
                                        type = "text/html";
                                        tag = "DNSBL";
                                        code = 200;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Resultado da checagem do IP<br>" + ip;
                                        } else {
                                            message = "Check result of IP<br>" + ip;
                                        }
                                        result = getDNSBLHTML(
                                                SECURED, parameterMap, locale,
                                                user, client, ip, message
                                        );
                                    }
                                } else if (isSignatureURL(query)) {
                                    try {
                                        index = query.lastIndexOf('.');
                                        String token = query.substring(0, index);
                                        String url = Core.decompressAsString(token);
                                        type = "text/html";
                                        tag = "URIBL";
                                        code = 200;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Resultado da checagem da URL<br>" + url;
                                        } else {
                                            message = "Check the result of URL<br>" + url;
                                        }
                                        result = getDNSBLHTML(
                                                SECURED, parameterMap, locale,
                                                user, client, query, message
                                        );
                                    } catch (Exception ex) {
                                        type = "text/html";
                                        tag = "URIBL";
                                        code = 500;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "O identificador informado não é uma URL válida.";
                                        } else {
                                            message = "The reported identifier is not a valid URL.";
                                        }
                                        result = getMessageHMTL(locale, title, message);
                                    }
                                } else if (isHostname(query)) {
                                    type = "text/html";
                                    tag = "DNSBL";
                                    code = 200;
                                    String hostname = Domain.normalizeHostname(query, false);
                                    String redirectURL = null;
                                    if (!Domain.isRootDomain(query)) {
                                        boolean blocked = Block.containsFQDN(hostname);
                                        for (String ip : Reverse.getAddressSetSafe(hostname)) {
                                            if (Block.containsCIDR(ip)) {
                                                redirectURL = "./" + ip;
                                                break;
                                            } else if (blocked && Block.tryAdd(ip)) {
                                                redirectURL = "./" + ip;
                                                break;
                                            }
                                        }
                                    }
                                    if (redirectURL == null) {
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Resultado da checagem do domínio<br>" + hostname;
                                        } else {
                                            message = "Check the result of domain<br>" + hostname;
                                        }
                                        result = getDNSBLHTML(
                                                SECURED, parameterMap, locale,
                                                user, client, hostname, message
                                        );
                                    } else {
                                        result = getRedirectHTML(locale, redirectURL);
                                    }
                                } else {
                                    type = "text/html";
                                    tag = "DNSBL";
                                    code = 500;
                                    String message;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        message = "O identificador informado não é um IP nem um domínio válido.";
                                    } else {
                                        message = "Informed identifier is not a valid IP or a valid domain.";
                                    }
                                    result = getMessageHMTL(locale, title, message);
                                }
                            } else {
                                try {
                                    String ticket = command.substring(1);
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
                                        String query = Core.decodeHuffman(byteArray, 8);
                                        StringTokenizer tokenizer = new StringTokenizer(query, " ");
                                        String operator = tokenizer.nextToken();
                                        if (System.currentTimeMillis() - date > Server.WEEK_TIME) {
                                            String title;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                title = "Página do SPFBL";
                                            } else {
                                                title = "SPFBL page";
                                            }
                                            type = "text/html";
                                            tag = "HTTPC";
                                            code = 500;
                                            String message;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                message = "Ticket expirado.";
                                            } else {
                                                message = "Expired ticket.";
                                            }
                                            result = getMessageHMTL(locale, title, message);
                                        } else if (operator.equals("spam")) {
                                            try {
                                                String ip = null;
                                                String helo = null;
                                                String sender = null;
                                                String hostname = null;
                                                String recipient = null;
                                                userEmail = null;
                                                TreeSet<String> tokenSet = new TreeSet<>();
                                                while (tokenizer.hasMoreTokens()) {
                                                    String token = tokenizer.nextToken();
                                                    if (token.startsWith(">") && isValidEmail(token.substring(1))) {
                                                        recipient = token.substring(1);
                                                    } else if (token.endsWith(":") && isValidEmail(token.substring(0, token.length() - 1))) {
                                                        userEmail = token.substring(0, token.length() - 1);
                                                    } else if (token.startsWith("@") && isHostname(token.substring(1))) {
                                                        sender = token;
                                                        tokenSet.add(token);
                                                    } else if (Domain.isMailFrom(token)) {
                                                        sender = token;
                                                        tokenSet.add(token);
                                                    } else if (isHostname(token)) {
                                                        if (hostname == null || hostname.length() < token.length()) {
                                                            hostname = token;
                                                            helo = token;
                                                        }
                                                        tokenSet.add(token);
                                                    } else if (isValidIP(token)) {
                                                        ip = token;
                                                        tokenSet.add(token);
                                                    } else {
                                                        tokenSet.add(token);
                                                    }
                                                }
                                                if (hostname == null) {
                                                    hostname = Reverse.getValidHostname(ip);
                                                }
                                                type = "text/html";
                                                tag = "HTTPC";
                                                String title;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    title = "Página de denuncia SPFBL";
                                                } else {
                                                    title = "SPFBL complaint page";
                                                }
                                                User userTicket = User.get(userEmail);
                                                Query queryTicket = userTicket == null ? null : userTicket.getQuerySafe(date);
                                                if (queryTicket == null) {
                                                    if (sender == null) {
                                                        boolean whiteBlockForm = recipient != null;
                                                        TreeSet<String> complainSet = SPF.addComplain(origin, date, tokenSet, recipient);
                                                        tokenSet = SPF.expandTokenSet(tokenSet);
                                                        TreeSet<String> selectionSet = new TreeSet<>();
                                                        String message;
                                                        if (complainSet == null) {
                                                            complainSet = SPF.getComplain(ticket);
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "A mensagem já havia sido denunciada antes.";
                                                            } else {
                                                                message = "The message had been reported before.";
                                                            }
                                                        } else {
                                                            if (userEmail != null && sender != null && recipient != null) {
                                                                if (White.dropExact(userEmail + ":" + sender + ";PASS>" + recipient)) {
                                                                    Server.logDebug(date, "WHITE DROP " + userEmail + ":" + sender + ";PASS>" + recipient);
                                                                }
                                                            }
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "A mensagem foi denunciada com sucesso.";
                                                            } else {
                                                                message = "The message has been reported as SPAM.";
                                                            }
                                                        }
                                                        for (String token : complainSet) {
                                                            if (!isValidIP(token)) {
                                                                selectionSet.add(token);
                                                            }
                                                        }
                                                        type = "text/html";
                                                        tag = "SPFSP";
                                                        code = 200;
                                                        result = getComplainHMTL(
                                                                locale,
                                                                tokenSet, selectionSet,
                                                                message, whiteBlockForm
                                                        );
                                                    } else {
                                                        String blockKey = Block.keyBlockKey(
                                                                userEmail, ip, helo, sender,
                                                                hostname, "PASS", recipient
                                                        );
                                                        if (Block.containsExact(blockKey)) {
                                                            code = 200;
                                                            String message;
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "Este remetente está definitivamente bloqueado.";
                                                            } else {
                                                                message = "This sender is definitely blocked.";
                                                            }
                                                            result = getMessageHMTL(locale, title, message);
                                                        } else if (SPF.setSpam(date, tokenSet)) {
                                                            code = 200;
                                                            String message;
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "Mensagem denunciada com sucesso";
                                                            } else {
                                                                message = "Message complained successfully";
                                                            }
                                                            result = getComplainHMTL2(locale, queryTicket, message);
                                                        } else {
                                                            code = 200;
                                                            String message;
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "Esta mensagem já estava denunciada";
                                                            } else {
                                                                message = "This message was already reported";
                                                            }
                                                            result = getComplainHMTL2(locale, queryTicket, message);
                                                        }
                                                    }
                                                } else if (queryTicket.isBlockedForRecipient()) {
                                                    code = 200;
                                                    String message;
                                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                        message = "Este remetente está definitivamente bloqueado.";
                                                    } else {
                                                        message = "This sender is definitely blocked.";
                                                    }
                                                    result = getMessageHMTL(locale, title, message);
                                                } else if (queryTicket.setSpam(date)) {
                                                    code = 200;
                                                    String message;
                                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                        message = "Mensagem denunciada com sucesso";
                                                    } else {
                                                        message = "Message complained successfully";
                                                    }
                                                    result = getComplainHMTL2(locale, queryTicket, message);
                                                } else {
                                                    code = 200;
                                                    String message;
                                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                        message = "Esta mensagem já estava denunciada";
                                                    } else {
                                                        message = "This message was already reported";
                                                    }
                                                    result = getComplainHMTL2(locale, queryTicket, message);
                                                }
                                            } catch (Exception ex) {
                                                type = "text/plain";
                                                tag = "SPFSP";
                                                code = 500;
                                                result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                                            }
                                        } else if (operator.equals("unblockpp") && Core.hasPayPalAccount()) {
                                            type = "text/html";
                                            tag = "BLOCK";
                                            code = 200;
                                            String title;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                title = "Página de desbloqueio do SPFBL";
                                            } else {
                                                title = "SPFBL unblock page";
                                            }
                                            try {
                                                String paypal_user = Core.getPayPalAccountUser();
                                                String paypal_password = Core.getPayPalAccountPassword();
                                                String paypal_signature = Core.getPayPalAccountSignature();
                                                userEmail = tokenizer.nextToken();
                                                String ip = tokenizer.nextToken();
                                                String paypal_token = tokenizer.nextToken().toUpperCase();
                                                String paypal_playerid = tokenizer.nextToken().toUpperCase();
                                                String paypal_price = tokenizer.nextToken();
                                                String paypal_currency = tokenizer.nextToken().toUpperCase();
                                                URL url = new URL("https://api-3t.paypal.com/nvp");
                                                HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
                                                con.setConnectTimeout(3000);
                                                con.setReadTimeout(30000);
                                                con.setRequestMethod("POST");
                                                con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
                                                String postParams = "USER=" + paypal_user
                                                        + "&PWD=" + paypal_password
                                                        + "&SIGNATURE=" + paypal_signature
                                                        + "&VERSION=114.0"
                                                        + "&METHOD=DoExpressCheckoutPayment"
                                                        + "&TOKEN=" + paypal_token
                                                        + "&PAYERID=" + paypal_playerid
                                                        + "&PAYMENTREQUEST_0_PAYMENTACTION=SALE"
                                                        + "&PAYMENTREQUEST_0_AMT=" + paypal_price
                                                        + "&PAYMENTREQUEST_0_CURRENCYCODE=" + paypal_currency
                                                        + "";
                                                con.setDoOutput(true);
                                                try (DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {
                                                    wr.write(postParams.getBytes("UTF-8"));
                                                    wr.flush();
                                                }
                                                StringBuilder response;
                                                try (BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
                                                    String inputLine;
                                                    response = new StringBuilder();
                                                    while ((inputLine = in.readLine()) != null) {
                                                        response.append(inputLine);
                                                    }
                                                } catch (Exception ex) {
                                                    Server.logError(ex);
                                                    response = null;
                                                }
                                                if (response == null) {
                                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                        result = getMessageHMTL(
                                                                locale, title,
                                                                "O serviço do PayPal se encontra indisponível neste momento. "
                                                                + "Tente novamente mais tarde."
                                                        );
                                                    } else {
                                                        result = getMessageHMTL(
                                                                locale, title,
                                                                "The PayPal service is currently unavailable. "
                                                                + "Try again later."
                                                        );
                                                    }
                                                } else {
                                                    String decoded = URLDecoder.decode(response.toString(), "UTF-8");
                                                    Server.logTrace(postParams + " => " + decoded);
                                                    Properties properties = new Properties();
                                                    properties.load(new StringReader(decoded.replace("&", "\n")));
                                                    if (properties.getProperty("ACK").startsWith("Success")) {
                                                        String message;
                                                        if (Block.clearCIDR(null, ip, userEmail)) {
                                                            TreeSet<String> tokenSet = Reverse.getPointerSetSafe(ip);
                                                            tokenSet.add(userEmail);
                                                            String fqdn = FQDN.discoverFQDN(ip);
                                                            if (fqdn == null) {
                                                                Abuse.put(ip, userEmail);
                                                            } else {
                                                                Abuse.put(fqdn, userEmail);
                                                                tokenSet.add(fqdn);
                                                            }
                                                            NoReply.dropSafe(userEmail);
                                                            Trap.dropSafe(userEmail);
                                                            String block;
                                                            for (String token : tokenSet) {
                                                                while ((block = Block.find(null, null, token, false, true, true, false)) != null) {
                                                                    if (Block.dropExact(block)) {
                                                                        Server.logDebug(date, "false positive BLOCK '" + block + "' detected by '" + userEmail + "'.");
                                                                    }
                                                                }
                                                            }
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "O IP " + ip + " foi desmarcado com sucesso.";
                                                            } else {
                                                                message = "The IP " + ip + " was successfully unflagged.";
                                                            }
                                                        } else {
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "O IP " + ip + " já estava desmarcado.";
                                                            } else {
                                                                message = "The IP " + ip + " was already unflagged.";
                                                            }
                                                        }
                                                        result = getMessageHMTL(locale, title, message);
                                                    } else if (properties.getProperty("ACK").equals("Failure") && properties.getProperty("L_ERRORCODE0").equals("10417")) {
                                                        Server.logDebug(postParams + " => " + decoded);
                                                        String urlPayPal = "https://www.paypal.com/cgi-bin/webscr?cmd=_express-checkout&token=" + paypal_token;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Este IP não pode ser desmarcado por conta do "
                                                                    + "PayPal não ter reconhecido o método de pagamento escolhido. "
                                                                    + "Você será redirecionado automaticamente ao PayPal...";
                                                        } else {
                                                            message = "This IP can not be unflagged on behalf of the "
                                                                    + "PayPal not recognized the chosen payment method. "
                                                                    + "You will be automatically redirected to PayPal...";
                                                        }
                                                        result = getRedirectHMTL(
                                                                locale, title, message, urlPayPal, 10
                                                        );
                                                    } else if (properties.getProperty("ACK").equals("Failure") && properties.getProperty("L_ERRORCODE0").equals("10486")) {
                                                        Server.logDebug(postParams + " => " + decoded);
                                                        String urlPayPal = "https://www.paypal.com/cgi-bin/webscr?cmd=_express-checkout&token=" + paypal_token;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Este IP não pode ser desmarcado por conta do "
                                                                    + "PayPal não ter confirmado deste pagamento. "
                                                                    + "Você será redirecionado automaticamente ao PayPal...";
                                                        } else {
                                                            message = "This IP can not be unflagged on behalf of the "
                                                                    + "PayPal has not confirmed this payment. "
                                                                    + "You will be automatically redirected to PayPal...";
                                                        }
                                                        result = getRedirectHMTL(
                                                                locale, title, message, urlPayPal, 10
                                                        );
                                                    } else if (properties.getProperty("ACK").equals("Failure") && properties.getProperty("L_ERRORCODE0").equals("10411")) {
                                                        Server.logDebug(postParams + " => " + decoded);
                                                        String redirectURL = "./" + ip;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Este IP não pode ser desmarcado "
                                                                    + "por conta desta sessão do PayPal ter expirado. "
                                                                    + "Você será redirecionado automaticamente "
                                                                    + "para a página de delist...";
                                                        } else {
                                                            message = "This IP can not be unflagged because "
                                                                    + "this PayPal session has expired. "
                                                                    + "You will be redirected automatically "
                                                                    + "to the delist page...";
                                                        }
                                                        result = getRedirectHMTL(
                                                                locale, title, message, redirectURL, 10
                                                        );
                                                    } else {
                                                        Server.logError(postParams + " => " + decoded);
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            result = getMessageHMTL(
                                                                    locale, title,
                                                                    "Este IP não pode ser desmarcado devido a um erro interno."
                                                            );
                                                        } else {
                                                            result = getMessageHMTL(
                                                                    locale, title,
                                                                    "This IP can not be unflagged due to an internal error."
                                                            );
                                                        }
                                                    }
                                                }
                                            } catch (Exception ex) {
                                                Server.logError(ex);
                                                type = "text/html";
                                                tag = "BLOCK";
                                                code = 500;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Ocorreu um erro no processamento desta solicitação: "
                                                            + ex.getMessage() == null ? "undefined error." : ex.getMessage();
                                                } else {
                                                    message = "There was an error processing this request: "
                                                            + ex.getMessage() == null ? "undefined error." : ex.getMessage();
                                                }
                                                result = getMessageHMTL(locale, title, message);
                                            }
                                        } else if (operator.equals("unblock") || operator.equals("delist")) {
                                            String title;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                title = "Página de desbloqueio do SPFBL";
                                            } else {
                                                title = "SPFBL unblock page";
                                            }
                                            try {
                                                String clientTicket = tokenizer.nextToken();
                                                String ip = tokenizer.nextToken();
                                                if (!tokenizer.hasMoreTokens()) {
                                                    type = "text/html";
                                                    tag = "BLOCK";
                                                    code = 200;
                                                    String message;
                                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                        message = "Para desbloquear o IP " + ip + ", "
                                                                + "resolva o desafio reCAPTCHA abaixo.";
                                                    } else {
                                                        message = "To unblock the IP " + ip + ", "
                                                                + "solve the CAPTCHA below.";
                                                    }
                                                    result = getUnblockDNSBLHMTL(locale, message);
                                                } else {
                                                    String sender = tokenizer.nextToken();
                                                    String recipient = tokenizer.nextToken();
                                                    String hostname = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                                                    String mx = Domain.extractHost(sender, true);
                                                    SPF.Qualifier qualifier = SPF.getQualifier(ip, sender, hostname, true);
                                                    if (qualifier != SPF.Qualifier.PASS) {
                                                        User userTicket = User.get(userEmail);
                                                        Query queryTicket = userTicket == null ? null : userTicket.getQuerySafe(date);
                                                        if (queryTicket != null && queryTicket.isSigned(sender)) {
                                                            qualifier = SPF.Qualifier.PASS;
                                                        }
                                                    }
                                                    if (qualifier == SPF.Qualifier.PASS) {
                                                        clientTicket = clientTicket == null ? "" : clientTicket + ':';
                                                        String origem = Provider.containsExact(mx) ? sender : mx;
                                                        if (sender == null || recipient == null) {
                                                            type = "text/html";
                                                            tag = "BLOCK";
                                                            code = 500;
                                                            String message;
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "Este ticket de desbloqueio não "
                                                                        + "contém remetente e destinatário.";
                                                            } else {
                                                                message = "This release ticket does not "
                                                                        + "contains the sender and recipient.";
                                                            }
                                                            result = getMessageHMTL(locale, title, message);
                                                        } else if (White.containsExact(clientTicket + origem + ";PASS>" + recipient)) {
                                                            type = "text/html";
                                                            tag = "BLOCK";
                                                            code = 200;
                                                            String message;
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "O destinatário " + recipient + " "
                                                                        + "já autorizou o recebimento de mensagens "
                                                                        + "do remetente " + sender + ".";
                                                            } else {
                                                                message = "The recipient " + recipient + " "
                                                                        + "already authorized receiving messages "
                                                                        + "from sender " + sender + ".";
                                                            }
                                                            result = getMessageHMTL(locale, title, message);
                                                        } else if (Block.containsExact(clientTicket + origem + ";PASS>" + recipient)) {
                                                            type = "text/html";
                                                            tag = "BLOCK";
                                                            code = 200;
                                                            String message;
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "O destinatário " + recipient + " "
                                                                        + "não decidiu se quer receber mensagens "
                                                                        + "do remetente " + sender + ".\n"
                                                                        + "Para que a reputação deste remetente "
                                                                        + "não seja prejudicada neste sistema, "
                                                                        + "é necessário que ele pare de tentar "
                                                                        + "enviar mensagens para este "
                                                                        + "destinatário até a sua decisão.\n"
                                                                        + "Cada tentativa de envio por ele, "
                                                                        + "conta um ponto negativo na "
                                                                        + "reputação dele neste sistema.";
                                                            } else {
                                                                message = "The recipient " + recipient + " "
                                                                        + "not decided whether to receive messages "
                                                                        + "from sender " + sender + ".\n"
                                                                        + "For the reputation of the sender "
                                                                        + "is not impaired in this system, "
                                                                        + "it needs to stop trying to "
                                                                        + "send messages to this "
                                                                        + "recipient until its decision.\n"
                                                                        + "Each attempt to send him, "
                                                                        + "has a negative point in "
                                                                        + "reputation in this system.";
                                                            }
                                                            result = getMessageHMTL(locale, title, message);
                                                        } else {
                                                            type = "text/html";
                                                            tag = "BLOCK";
                                                            code = 200;
                                                            String message;
                                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                                message = "Para solicitar desbloqueio do envio feito do remetente " + sender + " "
                                                                        + "para o destinatário " + recipient + ", "
                                                                        + "favor preencher o captcha abaixo.";
                                                            } else {
                                                                message = "To request unblocking from the sender " + sender + " "
                                                                        + "to the recipient " + recipient + ", "
                                                                        + "solve the challenge reCAPTCHA below.";
                                                            }
                                                            result = getUnblockHMTL(locale, message);
                                                        }
                                                    } else {
                                                        type = "text/html";
                                                        tag = "BLOCK";
                                                        code = 500;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "O IP " + ip + " não está autorizado no registro SPF do domínio " + mx + ".\n"
                                                                    + "Para que seja possível solicitar o desbloqueio ao destinatário, por meio deste sistema, "
                                                                    + "configure o SPF deste domínio de modo que o envio por meio do mesmo IP resulte em PASS.\n"
                                                                    + "Após fazer esta modificação, aguarde algumas horas pela propagação DNS, "
                                                                    + "e volte a acessar esta mesma página para prosseguir com o processo de desbloqueio.";
                                                        } else {
                                                            message = "The IP " + ip + " is not authorized in the SPF record of domain " + mx + ".\n"
                                                                    + "To be able to request unblocking to recipient, through this system, "
                                                                    + "set the SPF record of this domain so that sending through the same IP results in PASS.\n"
                                                                    + "After making this change, wait a few hours for DNS propagation, "
                                                                    + "and re-access the same page to proceed with the unblock process.";
                                                        }
                                                        result = getMessageHMTL(locale, title, message);
                                                    }
                                                }
                                            } catch (Exception ex) {
                                                Server.logError(ex);
                                                type = "text/html";
                                                tag = "BLOCK";
                                                code = 500;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Ocorreu um erro no processamento desta solicitação: "
                                                            + ex.getMessage() == null ? "undefined error." : ex.getMessage();
                                                } else {
                                                    message = "There was an error processing this request: "
                                                            + ex.getMessage() == null ? "undefined error." : ex.getMessage();
                                                }
                                                result = getMessageHMTL(locale, title, message);
                                            }
                                        } else if (operator.equals("holding")) {
                                            String title;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                title = "Página de liberação do SPFBL";
                                            } else {
                                                title = "SPFBL release page";
                                            }
                                            String email = tokenizer.nextToken();
                                            User userLocal = User.get(email);
                                            Query queryLocal = userLocal == null ? null : userLocal.getQuerySafe(date);
                                            if (queryLocal == null) {
                                                type = "text/html";
                                                tag = "HOLDN";
                                                code = 500;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Este ticket de liberação não existe mais.";
                                                } else {
                                                    message = "This release ticket does not exist any more.";
                                                }
                                                result = getMessageHMTL(locale, title, message);
                                            } else if (queryLocal.isResult("WHITE")) {
                                                type = "text/html";
                                                tag = "HOLDN";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Esta mensagem já foi entregue.";
                                                } else {
                                                    message = "This message has already been delivered.";
                                                }
                                                result = getMessageHMTL(locale, title, message);
                                            } else if (queryLocal.isWhiteKey()) {
                                                type = "text/html";
                                                tag = "HOLDN";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Esta mensagem já foi liberada.";
                                                } else {
                                                    message = "This message has already been released.";
                                                }
                                                result = getMessageHMTL(locale, title, message);
                                            } else if (queryLocal.isBlockKey()) {
                                                type = "text/html";
                                                tag = "HOLDN";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Esta mensagem foi definitivamente bloqueada.";
                                                } else {
                                                    message = "This message has been permanently blocked.";
                                                }
                                                result = getMessageHMTL(locale, title, message);
                                            } else if (queryLocal.isRecipientAdvised()) {
                                                type = "text/html";
                                                tag = "HOLDN";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "O destinatário ainda não decidiu pela liberação desta mensagem.";
                                                } else {
                                                    message = "The recipient has not yet decided to release this message.";
                                                }
                                                result = getMessageHMTL(locale, title, message);
                                            } else {
                                                type = "text/html";
                                                tag = "HOLDN";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Para solicitar liberação desta mensagem, "
                                                            + "resolva o CAPTCHA abaixo.";
                                                } else {
                                                    message = "To request release of this message, "
                                                            + "solve the CAPTCHA below.";
                                                }
                                                result = getRequestHoldHMTL(locale, message);
                                            }
                                        } else if (operator.equals("unholdadmin")) {
                                            String title;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                title = "Página de liberação do SPFBL";
                                            } else {
                                                title = "SPFBL release page";
                                            }
                                            try {
                                                String email = tokenizer.nextToken();
                                                String blockKey = tokenizer.nextToken();
                                                blockKey = blockKey.replace('+', '=').toUpperCase();
                                                blockKey = new String(Core.BASE32STANDARD.decode(blockKey));
                                                TreeMap<Long,Query> querieMap = User.getQueries(email, date, blockKey);
                                                if (querieMap == null) {
                                                    type = "text/html";
                                                    tag = "UHOLD";
                                                    code = 500;
                                                    String message;
                                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                        message = "Este ticket de liberação não existe mais.";
                                                    } else {
                                                        message = "This release ticket does not exist any more.";
                                                    }
                                                    result = getMessageHMTL(locale, title, message);
                                                } else if (querieMap.isEmpty()) {
                                                    type = "text/html";
                                                    tag = "UHOLD";
                                                    code = 200;
                                                    String message;
                                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                        message = "Estas mensagens já foram entregues.";
                                                    } else {
                                                        message = "These messages has already been delivered.";
                                                    }
                                                    result = getMessageHMTL(locale, title, message);
                                                } else {
                                                    String sender = null;
                                                    boolean released = true;
                                                    for (long timeKey : querieMap.keySet()) {
                                                        Query queryLocal = querieMap.get(timeKey);
                                                        String whiteKey = queryLocal.getWhiteKey();
                                                        sender = queryLocal.getTrueSender();
                                                        if (!White.containsExtact(Core.getAdminEmail(), whiteKey)) {
                                                            released = false;
                                                            break;
                                                        }
                                                    }
                                                    if (released) {
                                                        type = "text/html";
                                                        tag = "UHOLD";
                                                        code = 200;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Estas mensagens já foram liberadas.";
                                                        } else {
                                                            message = "These messages has already been released.";
                                                        }
                                                        result = getMessageHMTL(locale, title, message);
                                                    } else if (sender == null) {
                                                        type = "text/html";
                                                        tag = "UHOLD";
                                                        code = 200;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Deseja mesmo liberar estas mensagens?";
                                                        } else {
                                                            message = "Do you really want to release these messages?";
                                                        }
                                                        result = getReleaseHoldHMTL(locale, message);
                                                    } else {
                                                        type = "text/html";
                                                        tag = "UHOLD";
                                                        code = 200;
                                                        String message;
                                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                            message = "Deseja mesmo liberar as mensagens do remetente " + sender + "?";
                                                        } else {
                                                            message = "Do you really want to release messages from " + sender + "?";
                                                        }
                                                        result = getReleaseHoldHMTL(locale, message);
                                                    }
                                                }
                                            } catch (Exception ex) {
                                                type = "text/plain";
                                                tag = "UHOLD";
                                                code = 500;
                                                result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                                            }
                                        } else if (operator.equals("unhold")) {
                                            String title;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                title = "Página de liberação do SPFBL";
                                            } else {
                                                title = "SPFBL release page";
                                            }
                                            String email = tokenizer.nextToken();
                                            Query queryLocal;
                                            if (Core.isAdminEmail(email)) {
                                                queryLocal = User.getAnyQuery(date);
                                            } else {
                                                User userLocal = User.get(email);
                                                locale = userLocal == null ? locale : userLocal.getLocale();
                                                timeZone = userLocal == null ? timeZone : userLocal.getTimeZone();
                                                DateFormat dateFormat = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM, locale);
                                                dateFormat.setTimeZone(timeZone);
                                                queryLocal = userLocal == null ? null : userLocal.getQuerySafe(date);
                                            }
                                            if (queryLocal == null) {
                                                type = "text/html";
                                                tag = "UHOLD";
                                                code = 500;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Este ticket de liberação não existe mais.";
                                                } else {
                                                    message = "This release ticket does not exist any more.";
                                                }
                                                result = getMessageHMTL(locale, title, message);
                                            } else if (Core.isAdminEmail(email)) {
                                                String whiteKey = queryLocal.getWhiteKey();
                                                if (White.containsExtact(email, whiteKey)) {
                                                    type = "text/html";
                                                    tag = "UHOLD";
                                                    code = 200;
                                                    String message;
                                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                        message = "Esta mensagem já foi liberada.";
                                                    } else {
                                                        message = "This message has already been released.";
                                                    }
                                                    result = getMessageHMTL(locale, title, message);
                                                } else {
                                                    type = "text/html";
                                                    tag = "UHOLD";
                                                    code = 200;
                                                    String message;
                                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                        message = "Deseja mesmo liberar esta mensagem?";
                                                    } else {
                                                        message = "Do you really want to release this message?";
                                                    }
                                                    result = getReleaseHoldHMTL(locale, message);
                                                }
                                            } else if (queryLocal.isDelivered()) {
                                                type = "text/html";
                                                tag = "UHOLD";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Esta mensagem já foi entregue.";
                                                } else {
                                                    message = "This message has already been delivered.";
                                                }
                                                result = getMessageHMTL(locale, title, message);
                                            } else if (!queryLocal.isHolding()) {
                                                type = "text/html";
                                                tag = "UHOLD";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Esta mensagem foi descartada antes que pudesse ser liberada.";
                                                } else {
                                                    message = "This message was discarded before it could be released.";
                                                }
                                                result = getMessageHMTL(locale, title, message);
                                            } else if (queryLocal.isWhiteKey()) {
                                                type = "text/html";
                                                tag = "UHOLD";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Esta mensagem já foi liberada e será entregue em breve.";
                                                } else {
                                                    message = "This message has already been released and will be delivered shortly.";
                                                }
                                                result = getMessageHMTL(locale, title, message);
                                            } else {
                                                type = "text/html";
                                                tag = "UHOLD";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Deseja mesmo liberar esta mensagem?";
                                                } else {
                                                    message = "Do you really want to release this message?";
                                                }
                                                result = getReleaseHoldHMTL(locale, message);
                                            }
                                        } else if (operator.equals("block") || operator.equals("ban") || operator.equals("bansubject")) {
                                            String title;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                title = "Página de bloqueio do SPFBL";
                                            } else {
                                                title = "SPFBL block page";
                                            }
                                            String email = tokenizer.nextToken();
                                            Query queryLocal;
                                            if (Core.isAdminEmail(email)) {
                                                queryLocal = User.getAnyQuery(date);
                                            } else {
                                                User userLocal = User.get(email);
                                                locale = userLocal == null ? locale : userLocal.getLocale();
                                                timeZone = userLocal == null ? timeZone : userLocal.getTimeZone();
                                                DateFormat dateFormat = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM, locale);
                                                dateFormat.setTimeZone(timeZone);
                                                queryLocal = userLocal == null ? null : userLocal.getQuerySafe(date);
                                            }
                                            if (queryLocal == null) {
                                                type = "text/html";
                                                tag = "BLOCK";
                                                code = 500;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Este ticket de liberação não existe mais.";
                                                } else {
                                                    message = "This release ticket does not exist any more.";
                                                }
                                                result = getMessageHMTL(locale, title, message);
                                            } else if (Core.isAdminEmail(email)) {
                                                String blockKey = queryLocal.getBlockKey();
                                                if (Block.containsExact(email, blockKey)) {
                                                    type = "text/html";
                                                    tag = "BLOCK";
                                                    code = 200;
                                                    String message;
                                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                        message = "Esta mensagem já foi bloqueada.";
                                                    } else {
                                                        message = "This message has already been blocked.";
                                                    }
                                                    result = getMessageHMTL(locale, title, message);
                                                } else {
                                                    type = "text/html";
                                                    tag = "BLOCK";
                                                    code = 200;
                                                    String message;
                                                    String text;
                                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                        message = "A mensagem foi retida por suspeita de SPAM";
                                                        text = "Confirma o bloqueio deste remetente?";
                                                    } else {
                                                        message = "The message was retained on suspicion of SPAM";
                                                        text = "Do you confirm the blocking of this sender?";
                                                    }
                                                    result = getBlockHMTL(locale, message, text);
                                                }
                                            } else if (queryLocal.isResult("ACCEPT") && queryLocal.isWhiteKey()) {
                                                type = "text/html";
                                                tag = "BLOCK";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Esta remetente foi liberado por outro usuário.";
                                                } else {
                                                    message = "This sender has been released by another user.";
                                                }
                                                result = getMessageHMTL(locale, title, message);
                                            } else if (queryLocal.isResult("ACCEPT") && queryLocal.isBlockKey()) {
                                                type = "text/html";
                                                tag = "BLOCK";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Esta remetente já foi bloqueado.";
                                                } else {
                                                    message = "This message has already been discarded.";
                                                }
                                                result = getMessageHMTL(locale, title, message);
                                            } else if (queryLocal.isResult("ACCEPT")) {
                                                type = "text/html";
                                                tag = "BLOCK";
                                                code = 200;
                                                String message;
                                                String text;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Mensagem com forte suspeita de SPAM";
                                                    text = "Confirma o bloqueio deste remetente?";
                                                } else {
                                                    message = "Message with strong suspicion of SPAM";
                                                    text = "Do you confirm the blocking of this sender?";
                                                }
                                                result = getBlockHMTL(locale, message, text);
                                            } else if (queryLocal.isResult("BLOCK") || queryLocal.isResult("REJECT")) {
                                                type = "text/html";
                                                tag = "BLOCK";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Esta mensagem já foi descartada.";
                                                } else {
                                                    message = "This message has already been discarded.";
                                                }
                                                result = getMessageHMTL(locale, title, message);
                                            } else if (queryLocal.isWhiteKey()) {
                                                type = "text/html";
                                                tag = "BLOCK";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Esta mensagem foi liberada por outro usuário.";
                                                } else {
                                                    message = "This message has been released by another user.";
                                                }
                                                result = getMessageHMTL(locale, title, message);
                                            } else if (queryLocal.isBlockKey()) {
                                                type = "text/html";
                                                tag = "BLOCK";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Esta mensagem já foi bloqueada e será descartada em breve.";
                                                } else {
                                                    message = "This message has already been blocked and will be discarded soon.";
                                                }
                                                result = getMessageHMTL(locale, title, message);
                                            } else {
                                                type = "text/html";
                                                tag = "BLOCK";
                                                code = 200;
                                                String message;
                                                String text;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "A mensagem foi retida por suspeita de SPAM";
                                                    text = "Confirma o bloqueio deste remetente?";
                                                } else {
                                                    message = "The message was retained on suspicion of SPAM";
                                                    text = "Do you confirm the blocking of this sender?";
                                                }
                                                result = getBlockHMTL(locale, message, text);
                                            }
                                        } else if (operator.equals("unsubscribe")) {
                                            try {
                                                String email = tokenizer.nextToken();
                                                type = "text/html";
                                                tag = "CANCE";
                                                code = 200;
                                                String message;
                                                String text;
                                                if (NoReply.isUnsubscribed(email)) {
                                                    String title;
                                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                        title = "Página de cancelamento do SPFBL";
                                                        message = "O sistema de alerta já estava cancelado para " + email + ".";
                                                    } else {
                                                        title = "SPFBL unsubscribe page";
                                                        message = "The warning system was already unsubscribed for " + email + ".";
                                                    }
                                                    result = getMessageHMTL(locale, title, message);
                                                } else {
                                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                        message = "Cancelamento de alertas do SPFBL";
                                                        text = "O cancelamento de alertas pode prejudicar a interação com este sistema.\n"
                                                                + "Se tiver certeza que quer cancelar estes alertas para " + email + ", resolva o reCAPTCHA:";
                                                    } else {
                                                        message = "Unsubscribing SPFBL alerts.";
                                                        text = "Canceling alerts can impair interaction with this system.\n"
                                                                + "If you are sure you want to cancel these alerts for " + email + ", resolve reCAPTCHA:";
                                                    }
                                                    result = getUnsubscribeHMTL(locale, message, text);
                                                }
                                            } catch (Exception ex) {
                                                type = "text/plain";
                                                tag = "CANCE";
                                                code = 500;
                                                result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                                            }
                                        } else if (operator.equals("release")) {
                                            String title;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                title = "Página de liberação do SPFBL";
                                            } else {
                                                title = "SPFBL release page";
                                            }
                                            try {
                                                String id = tokenizer.nextToken();
                                                Defer defer = Defer.getDefer(date, id);
                                                if (defer == null) {
                                                    type = "text/html";
                                                    tag = "DEFER";
                                                    code = 500;
                                                    String message;
                                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                        message = "Este ticket de liberação não existe ou já foi liberado antes.";
                                                    } else {
                                                        message = "This release ticket does not exist or has been released before.";
                                                    }
                                                    result = getMessageHMTL(locale, title, message);
                                                } else if (defer.isReleased()) {
                                                    type = "text/html";
                                                    tag = "DEFER";
                                                    code = 200;
                                                    String message;
                                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                        message = "Sua mensagem já havia sido liberada.";
                                                    } else {
                                                        message = "Your message had already been freed.";
                                                    }
                                                    result = getMessageHMTL(locale, title, message);
                                                } else {
                                                    type = "text/html";
                                                    tag = "DEFER";
                                                    code = 200;
                                                    String message;
                                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                        message = "Para liberar o recebimento da mensagem, "
                                                                + "resolva o desafio reCAPTCHA abaixo.";
                                                    } else {
                                                        message = "To release the receipt of the message, "
                                                                + "solve the CAPTCHA below.";
                                                    }
                                                    result = getReleaseHMTL(locale, message);
                                                }
                                            } catch (Exception ex) {
                                                type = "text/html";
                                                tag = "DEFER";
                                                code = 500;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Ocorreu um erro no processamento desta solicitação: "
                                                            + ex.getMessage() == null ? "undefined error." : ex.getMessage();
                                                } else {
                                                    message = "There was an error processing this request: "
                                                            + ex.getMessage() == null ? "undefined error." : ex.getMessage();
                                                }
                                                result = getMessageHMTL(locale, title, message);
                                            }
                                        } else if (operator.equals("white")) {
                                            String title;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                title = "Página de desbloqueio do SPFBL";
                                            } else {
                                                title = "SPFBL unblock page";
                                            }
                                            try {
                                                String white = White.normalizeTokenWhite(tokenizer.nextToken());
                                                String clientTicket = tokenizer.nextToken();
                                                white = clientTicket + white;
                                                String ip = tokenizer.nextToken();
                                                String sender = tokenizer.nextToken();
                                                String recipient = tokenizer.nextToken();
                                                String hostname = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                                                if (sentUnblockConfirmationSMTP.containsKey(command.substring(1))) {
                                                    type = "text/html";
                                                    tag = "WHITE";
                                                    code = 200;
                                                    result = enviarConfirmacaoDesbloqueio(
                                                            SECURED, command.substring(1),
                                                            recipient, sender, locale
                                                    );
                                                } else if (White.containsExact(white)) {
                                                    type = "text/html";
                                                    tag = "WHITE";
                                                    code = 200;
                                                    String message;
                                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                        message = "Já houve liberação deste remetente "
                                                                + "" + sender + " pelo destinatário "
                                                                + "" + recipient + ".";
                                                    } else {
                                                        message = "There have been release from this sender "
                                                                + "" + sender + " by recipient "
                                                                + "" + recipient + ".";
                                                    }
                                                    result = getMessageHMTL(locale, title, message);
                                                } else {
                                                    type = "text/html";
                                                    tag = "WHITE";
                                                    code = 200;
                                                    String message;
                                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                        message = "Confirme se deseja desbloquear o remetente " + sender + ".";
                                                    } else {
                                                        message = "Confirm that you want to unlock the sender " + sender + ".";
                                                    }
                                                    result = getWhiteHMTL(locale, message);
                                                }
                                            } catch (Exception ex) {
                                                type = "text/html";
                                                tag = "WHITE";
                                                code = 500;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Ocorreu um erro no processamento desta solicitação: "
                                                            + ex.getMessage() == null ? "undefined error." : ex.getMessage();
                                                } else {
                                                    message = "There was an error processing this request: "
                                                            + ex.getMessage() == null ? "undefined error." : ex.getMessage();
                                                }
                                                result = getMessageHMTL(locale, title, message);
                                            }
                                        } else {
                                            type = "text/plain";
                                            tag = "HTTPC";
                                            code = 403;
                                            result = "Forbidden\n";
                                        }
                                    } else {
                                        type = "text/plain";
                                        tag = "HTTPC";
                                        code = 403;
                                        result = "Forbidden\n";
                                    }
                                } catch (Exception ex) {
                                    type = "text/plain";
                                    tag = "HTTPC";
                                    code = 403;
                                    result = "Forbidden\n";
                                }
                            }
                        } else if (request.equals("PUT")) {
                            if (command.startsWith("/spam/")) {
                                try {
                                    index = command.indexOf('/', 1) + 1;
                                    String ticket = command.substring(index);
                                    ticket = URLDecoder.decode(ticket, "UTF-8");
                                    TreeSet<String> complainSet = SPF.addComplain(origin, ticket);
                                    if (complainSet == null) {
                                        type = "text/plain";
                                        tag = "SPFSP";
                                        code = 404;
                                        result = "DUPLICATE COMPLAIN\n";
                                    } else {
                                        type = "text/plain";
                                        tag = "SPFSP";
                                        code = 200;
                                        String recipient = SPF.getRecipient(ticket);
                                        result = "OK " + complainSet + (recipient == null ? "" : " >" + recipient) + "\n";
                                    }
                                } catch (Exception ex) {
                                    type = "text/plain";
                                    tag = "SPFSP";
                                    code = 500;
                                    result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                                }
                            } else if (command.startsWith("/ham/")) {
                                try {
                                    index = command.indexOf('/', 1) + 1;
                                    String ticket = command.substring(index);
                                    ticket = URLDecoder.decode(ticket, "UTF-8");
                                    TreeSet<String> tokenSet = SPF.deleteComplain(origin, ticket);
                                    if (tokenSet == null) {
                                        type = "text/plain";
                                        tag = "SPFHM";
                                        code = 404;
                                        result = "ALREADY REMOVED\n";
                                    } else {
                                        type = "text/plain";
                                        tag = "SPFHM";
                                        code = 200;
                                        String recipient = SPF.getRecipient(ticket);
                                        result = "OK " + tokenSet + (recipient == null ? "" : " >" + recipient) + "\n";
                                    }
                                } catch (Exception ex) {
                                    type = "text/plain";
                                    tag = "SPFHM";
                                    code = 500;
                                    result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                                }
                            } else {
                                try {
                                    String ticket = command.substring(1);
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
                                            type = "text/plain";
                                            tag = "HTTPC";
                                            code = 500;
                                            result = "EXPIRED TICKET.\n";
                                        } else {
                                            String query = Core.decodeHuffman(byteArray, 8);
                                            StringTokenizer tokenizer = new StringTokenizer(query, " ");
                                            command = tokenizer.nextToken();
                                            if (command.equals("spam")) {
                                                try {
                                                    type = "text/plain";
                                                    tag = "SPFSP";
                                                    code = 200;
                                                    String sender = null;
                                                    String recipient = null;
                                                    String clientTicket = null;
                                                    TreeSet<String> tokenSet = new TreeSet<>();
                                                    while (tokenizer.hasMoreTokens()) {
                                                        String token = tokenizer.nextToken();
                                                        if (token.startsWith(">") && isValidEmail(token.substring(1))) {
                                                            recipient = token.substring(1);
                                                        } else if (token.endsWith(":") && isValidEmail(token.substring(0, token.length() - 1))) {
                                                            clientTicket = token.substring(0, token.length() - 1);
                                                        } else if (token.startsWith("@") && isHostname(token.substring(1))) {
                                                            sender = token;
                                                            tokenSet.add(token);
                                                        } else if (Domain.isMailFrom(token)) {
                                                            sender = token;
                                                            tokenSet.add(token);
                                                        } else {
                                                            tokenSet.add(token);
                                                        }
                                                    }
                                                    TreeSet<String> complainSet = SPF.addComplain(origin, date, tokenSet, recipient);
                                                    if (complainSet == null) {
                                                        result = "DUPLICATE COMPLAIN\n";
                                                    } else {
                                                        if (clientTicket != null && sender != null && recipient != null) {
                                                            if (White.dropExact(clientTicket + ":" + sender + ";PASS>" + recipient)) {
                                                                Server.logDebug(date, "WHITE DROP " + clientTicket + ":" + sender + ";PASS>" + recipient);
                                                            }
                                                        }
                                                        result = "OK " + complainSet + (recipient == null ? "" : " >" + recipient) + "\n";
                                                    }
                                                } catch (Exception ex) {
                                                    type = "text/plain";
                                                    tag = "SPFSP";
                                                    code = 500;
                                                    result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                                                }
                                            } else {
                                                type = "text/plain";
                                                tag = "HTTPC";
                                                code = 403;
                                                result = "Forbidden\n";
                                            }
                                        }
                                    } else {
                                        type = "text/plain";
                                        tag = "HTTPC";
                                        code = 403;
                                        result = "Forbidden\n";
                                    }
                                } catch (Exception ex) {
                                    type = "text/plain";
                                    tag = "HTTPC";
                                    code = 403;
                                    result = "Forbidden\n";
                                }
                            }
                        } else {
                            type = "text/plain";
                            tag = "HTTPC";
                            code = 405;
                            result = "Method not allowed.\n";
                        }
                    }
                    if (code > 0) {
                        try {
                            response(code, type, result, exchange);
                            command = (SECURED ? "HTTPS " : "HTTP ") + request + " " + command
                                    + (parameterMap == null ? "" : " " + parameterMap);
                            result = code + " " + type + " " + result;
                        } catch (IOException ex) {
                            result = ex.getMessage();
                        }
                    }
                    Server.logQuery(
                            time, tag,
                            origin,
                            null,
                            uri.toString(),
                            result
                    );
                }
            } catch (IOException ex) {
                // Do nothing.
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }

    private static final HashMap<String,Object> sentUnblockKeySMTP = new HashMap<>();
    private static final HashMap<String,String> emailUnblockKeySMTP = new HashMap<>();

    private static String getDesbloqueioHTML(
            boolean secured,
            final Locale locale,
            final String url,
            final String ip,
            String email
    ) {
        StringBuilder builder = new StringBuilder();
        Object resultSentSMTP = sentUnblockKeySMTP.get(ip);
        builder.append("<!DOCTYPE html>\n");
        builder.append("<html lang=\"");
        builder.append(locale.getLanguage());
        builder.append("\">\n");
        String title;
        String message;
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            title = "Página de checagem DNSBL";
            message = "Envio da chave de remoção";
        } else {
            title = "DNSBL check page";
            message = "Delist key delivery";
        }
        if (resultSentSMTP == null) {
            if (sentUnblockKeySMTP.containsKey(ip)) {
                buildHead(builder, title, Core.getURL(secured, locale, ip), 5);
            } else {
                emailUnblockKeySMTP.put(ip, email);
                sentUnblockKeySMTP.put(ip, null);
                buildHead(builder, title, Core.getURL(secured, locale, ip), 10);
                new Thread() {
                    @Override
                    public void run() {
                        try {
                            Thread.currentThread().setName("BCKGROUND");
                            String address = emailUnblockKeySMTP.get(ip);
                            sentUnblockKeySMTP.put(ip, enviarDesbloqueioDNSBL(locale, url, ip, address));
                        } catch (Exception ex) {
                            sentUnblockKeySMTP.put(ip, ex);
                        }
                    }
                }.start();
            }
        } else {
            buildHead(false, builder, title);
        }
        builder.append("  <body>\n");
        builder.append("    <div id=\"container\">\n");
        if (resultSentSMTP == null) {
            buildProcessing(builder);
            buildMessage(builder, message);
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "Estamos enviando a chave de remoção por SMTP. Aguarde...");
            } else {
                buildText(builder, "We are sending the delist key by SMTP. Wait...");
            }
        } else if (resultSentSMTP instanceof String) {
            buildAdvertise(builder);
            buildMessage(builder, message);
            sentUnblockKeySMTP.remove(ip);
            emailUnblockKeySMTP.remove(ip);
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "A chave de remoção foi enviada com sucesso com a seguinte confirmação de entrega:");
            } else {
                buildText(builder, "The delist key was successfully sent with the following delivery confirmation:");
            }
            String lastResponse = (String) resultSentSMTP;
            buildText(builder, StringEscapeUtils.escapeHtml4(lastResponse));
        } else if (resultSentSMTP instanceof SMTPAddressFailedException) {
            buildAdvertise(builder);
            buildMessage(builder, message);
            sentUnblockKeySMTP.remove(ip);
            email = emailUnblockKeySMTP.remove(ip);
            SMTPAddressFailedException afex = (SMTPAddressFailedException) resultSentSMTP;
            if (afex.getReturnCode() / 100 == 5) {
                if (afex.getReturnCode() == 551 || afex.getMessage().contains(" 5.1.1 ") || afex.getMessage().contains("unknown") || afex.getMessage().contains("exist")) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        buildText(builder, "Chave de remoção não pode ser enviada porque o endereço escolhido não existe:");
                    } else {
                        buildText(builder, "Delist key can not be sent because the chosen address does not exist:");
                    }
                    buildText(builder, StringEscapeUtils.escapeHtml4(afex.getMessage()));
                    if (email != null && email.startsWith("postmaster@")) {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            buildText(builder, "A conta postmaster é requerida pela RFC 5321 então essa conta deve ser implementada.");
                        } else {
                            buildText(builder, "The postmaster account is required by RFC 5321 so this account must be implemented.");
                        }
                    } else {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            buildText(builder, "Tenha certeza de que este é o endereço correto para receber a chave de delist.");
                        } else {
                            buildText(builder, "Make sure this is the correct address to receive the delist key.");
                        }
                    }
                } else {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        buildText(builder, "Chave de remoção não pode ser enviada por recusa permanente pelo MX de destino:");
                    } else {
                        buildText(builder, "Delist key can not be sent for permanent denial by the destination MX:");
                    }
                    buildText(builder, StringEscapeUtils.escapeHtml4(afex.getMessage()));
                    if (email != null && email.startsWith("postmaster@")) {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            buildText(builder, "Você deve remover qualquer filtro para a conta postmaster pois a <a href=\"https://tools.ietf.org/html/rfc5321\">RFC 5321</a> não permite essa prática.");
                        } else {
                            buildText(builder, "You should remove any filter for the postmaster account because <a href=\"https://tools.ietf.org/html/rfc5321\">RFC 5321</a> does not allow this practice.");
                        }
                    } else if (Core.hasAdminEmail()) {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            buildText(builder, "Coloque o endereço " + Core.getAdminEmail() + " em whitelist para evitar esse problema.");
                        } else {
                            buildText(builder, "Put the " + Core.getAdminEmail() + " address on whitelist to avoid this problem.");
                        }
                    } else {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            buildText(builder, "Desative todos os filtros de rejeição do seu MX para evitar este problema.");
                        } else {
                            buildText(builder, "Disable all rejection filters on your MX to avoid this problem.");
                        }
                    }
                }
            } else if (afex.getReturnCode() / 100 == 4) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Chave de remoção não pode ser enviada por recusa temporária pelo MX de destino:");
                } else {
                    buildText(builder, "Delist key can not be sent for temporary denial by the destination MX:");
                }
                buildText(builder, StringEscapeUtils.escapeHtml4(afex.getMessage()));
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Aguarde alguns minutos e tente realizar este procedimento novamente.");
                } else {
                    buildText(builder, "Please wait for a few minutes and try performing this procedure again.");
                }
            } else {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Chave de remoção não pode ser enviada por rejeição desconhecia do MX de destino:");
                } else {
                    buildText(builder, "Delist key can not be sent for unknown rejection of destination MX:");
                }
                buildText(builder, StringEscapeUtils.escapeHtml4(afex.getMessage()));
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Consulte o administrador deste MX para resolver este problema.");
                } else {
                    buildText(builder, "Please consult your MX administrator to resolve this issue.");
                }
            }
            
            
        } else if (resultSentSMTP instanceof SendFailedException) {
            buildAdvertise(builder);
            buildMessage(builder, message);
            sentUnblockKeySMTP.remove(ip);
            email = emailUnblockKeySMTP.remove(ip);
            SendFailedException ex = (SendFailedException) resultSentSMTP;
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "Chave de remoção não pode ser enviada devido a recusa do servidor de destino:\n");
            } else {
                buildText(builder, "Delist key can not be sent due to denial of destination server:\n");
            }
            buildText(builder, StringEscapeUtils.escapeHtml4(ex.getMessage()));
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "Consulte o administrador deste MX para resolver este problema.");
            } else {
                buildText(builder, "Please consult your MX administrator to resolve this issue.");
            }
        } else if (resultSentSMTP instanceof NameNotFoundException) {
            buildAdvertise(builder);
            buildMessage(builder, message);
            sentUnblockKeySMTP.remove(ip);
            emailUnblockKeySMTP.remove(ip);
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "Chave de remoção não pode ser enviada pois o MX de destino não existe.");
            } else {
                buildText(builder, "Delist key can not be sent because the destination MX does not exist.");
            }
        } else if (resultSentSMTP instanceof CommunicationException) {
            buildAdvertise(builder);
            buildMessage(builder, message);
            sentUnblockKeySMTP.remove(ip);
            emailUnblockKeySMTP.remove(ip);
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "Chave de remoção não pode ser enviada pois o DNS deste domínio está indisponível.");
            } else {
                buildText(builder, "Delist key can not be sent because the DNS of this domain is unavailable.");
            }
        } else if (resultSentSMTP instanceof ServiceUnavailableException) {
            buildAdvertise(builder);
            buildMessage(builder, message);
            sentUnblockKeySMTP.remove(ip);
            emailUnblockKeySMTP.remove(ip);
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "Chave de remoção não pode ser enviada pois o DNS deste domínio está indisponível.");
            } else {
                buildText(builder, "Delist key can not be sent because the DNS of this domain is unavailable.");
            }
        } else if (resultSentSMTP instanceof MailConnectException) {
            buildAdvertise(builder);
            buildMessage(builder, message);
            sentUnblockKeySMTP.remove(ip);
            email = emailUnblockKeySMTP.remove(ip);
            String hostname = Domain.normalizeHostname(email, false);
            if (Reverse.hasValidMailExchange(hostname)) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "A chave de remoção não pode ser enviada pois o MX do destino se encontra inalcançável.");
                } else {
                    buildText(builder, "The delist key can not be sent because the destination MX is unreachable.");
                }
            } else {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "A chave de remoção não pode ser enviada pois o domínio '" + hostname + "' não possui um registro MX válido.");
                } else {
                    buildText(builder, "The delist key can not be sent because the domain '" + hostname + "' does not have a valid MX record.");
                }
                try {
                    Attributes atributes = Server.getAttributesDNS(hostname, "MX");
                    Attribute attribute = atributes.get("MX");
                    if (attribute != null && attribute.size() > 0) {
                        builder.append("<ul>\n");
                        for (int index = 0; index < attribute.size(); index++) {
                            String mx = (String) attribute.get(index);
                            builder.append("   <li>");
                            builder.append(mx);
                            builder.append("</li>\n");
                        }
                        builder.append("</ul>\n");
                    }
                } catch (NamingException ex) {
                    // DO nothing.
                }
            }
        } else if (resultSentSMTP instanceof SocketConnectException) {
            buildAdvertise(builder);
            buildMessage(builder, message);
            emailUnblockKeySMTP.remove(ip);
            sentUnblockKeySMTP.remove(ip);
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "Chave de remoção não pode ser enviada pois o MX de destino recusou nossa conexão SMTP.");
                buildText(builder, "Para que o envio da chave seja possível, desative o firewall do seu MX.");
            } else {
                buildText(builder, "Delist key cannot be sent because the destination MX has declined our SMTP connection.");
                buildText(builder, "In order for the key to be sent, disable your MX firewall.");
            }
        } else if (resultSentSMTP instanceof SocketTimeoutException) {
            buildAdvertise(builder);
            buildMessage(builder, message);
            emailUnblockKeySMTP.remove(ip);
            sentUnblockKeySMTP.remove(ip);
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "Chave de remoção não pode ser enviada pois o MX de destino demorou demais para finalizar a transação SMTP.");
                buildText(builder, "Para que o envio da chave seja possível, o tempo total da transação SMTP não pode levar mais que um minuto.");
            } else {
                buildText(builder, "Delist key can not be sent because the destination MX took too long to complete the SMTP transaction.");
                buildText(builder, "For the key delivery is possible, the total time of the SMTP transaction can not take more than one minute.");
            }
        } else if (resultSentSMTP instanceof MessagingException) {
            buildAdvertise(builder);
            buildMessage(builder, message);
            emailUnblockKeySMTP.remove(ip);
            sentUnblockKeySMTP.remove(ip);
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "Chave de remoção não pode ser enviada pois o MX de destino está recusando nossa mensagem.");
            } else {
                buildText(builder, "Delist key can not be sent because the destination MX is declining our message.");
            }
        } else if (resultSentSMTP instanceof NamingException) {
            buildAdvertise(builder);
            buildMessage(builder, message);
            emailUnblockKeySMTP.remove(ip);
            sentUnblockKeySMTP.remove(ip);
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "Chave de remoção não pode ser enviada pois não foi possível consultar o MX do destino.");
                buildText(builder, "Para que o envio da chave seja possível, tenha certeza de que o serviço DNS do destino esteja funcionando adequadamente.");
            } else {
                buildText(builder, "Delist key can not be sent because the destination MX could not be queried.");
                buildText(builder, "In order for the key to be sent, make sure that the destination DNS service is working properly.");
            }
        } else if (resultSentSMTP instanceof Exception) {
            Server.logError((Exception) resultSentSMTP);
            buildAdvertise(builder);
            buildMessage(builder, message);
            emailUnblockKeySMTP.remove(ip);
            sentUnblockKeySMTP.remove(ip);
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "Não foi possível enviar a chave de remoção devido a uma falha de sistema.");
            } else {
                buildText(builder, "The delist key could not be sent due to a system failure.");
            }
        } else {
            buildAdvertise(builder);
            buildMessage(builder, message);
            emailUnblockKeySMTP.remove(ip);
            sentUnblockKeySMTP.remove(ip);
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "Não foi possível enviar a chave de remoção devido a uma falha de sistema.");
            } else {
                buildText(builder, "The delist key could not be sent due to a system failure.");
            }
        }
        buildFooter(builder, locale, null);
        builder.append("    </div>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private static Object enviarDesbloqueioDNSBL(
            Locale locale,
            String url,
            String ip,
            String email
    ) throws CommunicationException, SocketConnectException,
            SocketTimeoutException, MessagingException,
            NameNotFoundException, ServiceUnavailableException {
        if (url == null) {
            return false;
        } else if (!Core.hasOutputSMTP()) {
            return false;
        } else if (!Core.hasAdminEmail()) {
            return false;
        } else if (!isValidEmail(email)) {
            return false;
        } else if (NoReply.isUnsubscribed(email)) {
            return false;
        } else {
            try {
                User user = User.get(email);
                InternetAddress[] recipients;
                if (user == null) {
                    recipients = InternetAddress.parse(email);
                } else {
                    recipients = new InternetAddress[1];
                    recipients[0] = user.getInternetAddress();
                }
                MimeMessage message = Core.newMessage(false);
                message.addRecipients(Message.RecipientType.TO, recipients);
                String subject;
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    subject = "Chave de delist SPFBL para o IP " + ip;
                } else {
                    subject = "SPFBL delist key for IP " + ip;
                }
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
                loadStyleCSS(builder);
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildConfirmAction(
                            builder,
                            "Desbloquear IP",
                            url,
                            "Confirme o desbloqueio para o IP " + ip + " na DNSBL",
                            "SPFBL.net", "http://spfbl.net/"
                    );
                } else {
                    buildConfirmAction(
                            builder,
                            "Delist IP",
                            url,
                            "Confirm the delist of IP " + ip + " at DNSBL",
                            "SPFBL.net",
                            "http://spfbl.net/en/"
                    );
                }
                builder.append("  </head>\n");
                builder.append("  <body>\n");
                builder.append("    <div id=\"container\">\n");
                builder.append("      <div id=\"divlogo\">\n");
                builder.append("        <img src=\"cid:logo\">\n");
                builder.append("      </div>\n");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildMessage(builder, "Desbloqueio do IP " + ip + " na DNSBL");
                    buildText(
                            builder,
                            "Se você é o administrador deste IP, "
                            + "acesse esta URL para resolver o reCAPTCHA "
                            + "e finalizar o procedimento de desbloqueio:"
                    );
                    buildText(builder, "<a href=\"" + url + "\">" + url + "</a>");
                } else {
                    buildMessage(builder, "Delist of IP " + ip + " at DNSBL");
                    buildText(
                            builder,
                            "If you are the administrator of this IP, "
                            + "go to this URL to solve the reCAPTCHA "
                            + "and finish the delist procedure:"
                    );
                    buildText(builder, "<a href=\"" + url + "\">" + url + "</a>");
                }
                buildFooter(builder, locale, Core.getListUnsubscribeURL(locale, recipients[0]));
                builder.append("    </div>\n");
                builder.append("  </body>\n");
                builder.append("</html>\n");
                // Making HTML part.
                MimeBodyPart htmlPart = new MimeBodyPart();
                htmlPart.setContent(builder.toString(), "text/html;charset=UTF-8");
                // Making logo part.
                MimeBodyPart logoPart = new MimeBodyPart();
                File logoFile = Core.getLogoFile(user);
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
                return Core.getLastResponse(locale, message, 60000);
            } catch (NameNotFoundException ex) {
                throw ex;
            } catch (CommunicationException ex) {
                throw ex;
            } catch (MailConnectException ex) {
                throw ex;
            } catch (SocketConnectException ex) {
                throw ex;
            } catch (SocketTimeoutException ex) {
                throw ex;
            } catch (ServiceUnavailableException ex) {
                throw ex;
            } catch (SendFailedException ex) {
                if (ex.getCause() instanceof SMTPAddressFailedException) {
                    return ex.getCause();
                } else {
                    throw ex;
                }
            } catch (MessagingException ex) {
                throw ex;
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        }
    }

    public static boolean enviarOTP(
            Locale locale,
            User user
    ) {
        if (locale == null) {
            Server.logError("no locale defined.");
            return false;
        } else if (!Core.hasOutputSMTP()) {
            Server.logError("no SMTP account to send TOTP.");
            return false;
        } else if (!Core.hasAdminEmail()) {
            Server.logError("no admin e-mail to send TOTP.");
            return false;
        } else if (user == null) {
            Server.logError("no user definied to send TOTP.");
            return false;
        } else if (NoReply.isUnsubscribed(user.getEmail())) {
            Server.logError("cannot send TOTP because user is unsubscribed.");
            return false;
        } else {
            File qrcodeFile = null;
            try {
                Server.logInfo("sending TOTP by e-mail.");
                String secret = user.newSecretOTP();
                InternetAddress[] recipients = new InternetAddress[1];
                recipients[0] = user.getInternetAddress();
                MimeMessage message = Core.newMessage(true);
                message.addRecipients(Message.RecipientType.TO, recipients);
                String subject;
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    subject = "Chave TOTP do SPFBL";
                } else {
                    subject = "SPFBL TOTP key";
                }
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
                loadStyleCSS(builder);
                builder.append("  </head>\n");
                builder.append("  <body>\n");
                builder.append("    <div id=\"container\">\n");
                builder.append("      <div id=\"divlogo\">\n");
                builder.append("        <img src=\"cid:logo\">\n");
                builder.append("      </div>\n");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildMessage(builder, "Sua chave <a target=\"_blank\" href=\"http://spfbl.net/totp/\">TOTP</a> no sistema SPFBL em " + Core.getHostname());
                    buildText(builder, "Carregue o QRCode abaixo em seu Google Authenticator ou em outro aplicativo <a target=\"_blank\" href=\"http://spfbl.net/totp/\">TOTP</a> de sua preferência.");
                    builder.append("      <div id=\"divcaptcha\">\n");
                    builder.append("        <img src=\"cid:qrcode\"><br>\n");
                    builder.append("        ");
                    builder.append(secret);
                    builder.append("\n");
                    builder.append("      </div>\n");
                } else {
                    buildMessage(builder, "Your <a target=\"_blank\" href=\"http://spfbl.net/en/totp/\">TOTP</a> key in SPFBL system at " + Core.getHostname());
                    buildText(builder, "Load QRCode below on your Google Authenticator or on other application <a target=\"_blank\" href=\"http://spfbl.net/en/totp/\">TOTP</a> of your choice.");
                    builder.append("      <div id=\"divcaptcha\">\n");
                    builder.append("        <img src=\"cid:qrcode\"><br>\n");
                    builder.append("        ");
                    builder.append(secret);
                    builder.append("\n");
                    builder.append("      </div>\n");
                }
                buildFooter(builder, locale, Core.getListUnsubscribeURL(locale, recipients[0]));
                builder.append("    </div>\n");
                builder.append("  </body>\n");
                builder.append("</html>\n");
                // Making HTML part.
                MimeBodyPart htmlPart = new MimeBodyPart();
                htmlPart.setContent(builder.toString(), "text/html;charset=UTF-8");
                // Making logo part.
                MimeBodyPart logoPart = new MimeBodyPart();
                File logoFile = Core.getLogoFile(user);
                logoPart.attachFile(logoFile);
                logoPart.setContentID("<logo>");
                logoPart.addHeader("Content-Type", "image/png");
                logoPart.setDisposition(MimeBodyPart.INLINE);
                // Join both parts.
                MimeMultipart content = new MimeMultipart("related");
                content.addBodyPart(htmlPart);
                content.addBodyPart(logoPart);
                // Making QRcode part.
                String code = "otpauth://totp/" + Core.getHostname() + ":" + user.getEmail() + "?"
                        + "secret=" + secret + "&"
                        + "issuer=" + Core.getHostname();
                qrcodeFile = Core.getQRCodeTempFile(code);
                if (qrcodeFile != null) {
                    MimeBodyPart qrcodePart = new MimeBodyPart();
                    qrcodePart.attachFile(qrcodeFile);
                    qrcodePart.setContentID("<qrcode>");
                    qrcodePart.addHeader("Content-Type", "image/png");
                    qrcodePart.setDisposition(MimeBodyPart.INLINE);
                    content.addBodyPart(qrcodePart);
                }
                // Set multiplart content.
                message.setContent(content);
                message.saveChanges();
                // Enviar mensagem.
                if (ServerSMTP.sendMessage(locale, message, recipients, null)) {
                    return true;
                } else {
                    user.clearTransitionOTP();
                    return false;
                }
            } catch (SocketTimeoutException afex) {
                user.clearTransitionOTP();
                return false;
            } catch (SMTPAddressFailedException afex) {
                if (afex.getReturnCode() == 551 || afex.getMessage().contains(" 5.1.1 ")) {
                    Server.logError("cannot send TOTP because recipient not exists.");
                } else {
                    Server.logError(afex);
                }
                user.clearTransitionOTP();
                return false;
            } catch (SendFailedException ex) {
                Server.logError(ex);
                user.clearTransitionOTP();
                return false;
            } catch (Exception ex) {
                Server.logError(ex);
                user.clearTransitionOTP();
                return false;
            } finally {
                if (qrcodeFile != null) {
                    qrcodeFile.delete();
                }
            }
        }
    }

    private static boolean enviarDesbloqueio(
            String userEmail,
            String url,
            String remetente,
            String destinatario
    ) throws NameNotFoundException, SocketTimeoutException,
            SocketConnectException, SendFailedException,
            MessagingException, CommunicationException {
        if (url == null) {
            return false;
        } else if (!Core.hasOutputSMTP()) {
            return false;
        } else if (!isValidEmail(destinatario)) {
            return false;
        } else if (Trap.contaisAnything(destinatario)) {
            return false;
        } else {
            try {
                if (NoReply.isUnsubscribed(destinatario)) {
                    if (userEmail == null) {
                        return false;
                    } else {
                        destinatario = userEmail;
                    }
                }
                Locale locale = User.getLocale(destinatario);
                InternetAddress[] recipients = InternetAddress.parse(destinatario);
                MimeMessage message = Core.newMessage(true);
                message.setReplyTo(InternetAddress.parse(remetente));
                message.addRecipients(Message.RecipientType.TO, recipients);
                String subject;
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    subject = "Solicitação de envio SPFBL";
                } else {
                    subject = "SPFBL send request";
                }
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
                loadStyleCSS(builder);
                builder.append("  </head>\n");
                builder.append("  <body>\n");
                builder.append("    <div id=\"container\">\n");
                builder.append("      <div id=\"divlogo\">\n");
                builder.append("        <img src=\"cid:logo\">\n");
                builder.append("      </div>\n");
                buildMessage(builder, subject);
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Nosso servidor rejeitou uma ou mais mensagens do remetente " + remetente + " e o mesmo requisitou que seja feita a liberação para que novos e-mails possam ser entregues a você.");
                    buildText(builder, "Se você deseja receber e-mails de " + remetente + ", acesse o endereço abaixo e para iniciar o processo de liberação:");
                } else {
                    buildText(builder, "Our server has rejected one or more messages from the sender " + remetente + " and the same sender has requested that the release be made for new emails can be delivered to you.");
                    buildText(builder, "If you wish to receive emails from " + remetente + ", access the address below and to start the release process:");
                }
                buildText(builder, "<a href=\"" + url + "\">" + url + "</a>");
                buildFooter(builder, locale, Core.getListUnsubscribeURL(locale, recipients[0]));
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Após a liberação, peça para o remetente reenviar a mensagem anterior, pois foi rejeitada.");
                } else {
                    buildText(builder, "After the release, ask the sender to resend the previous message because it was rejected.");
                }
                builder.append("    </div>\n");
                builder.append("  </body>\n");
                builder.append("</html>\n");
                // Making HTML part.
                MimeBodyPart htmlPart = new MimeBodyPart();
                htmlPart.setContent(builder.toString(), "text/html;charset=UTF-8");
                // Making logo part.
                MimeBodyPart logoPart = new MimeBodyPart();
                File logoFile = Core.getLogoFile(User.get(userEmail));
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
                return ServerSMTP.sendMessage(locale, message, recipients, null);
            } catch (NameNotFoundException ex) {
                throw ex;
            } catch (CommunicationException ex) {
                throw ex;
            } catch (MailConnectException ex) {
                throw ex;
            } catch (SocketConnectException ex) {
                throw ex;
            } catch (SocketTimeoutException ex) {
                throw ex;
            } catch (SendFailedException ex) {
                throw ex;
            } catch (MessagingException ex) {
                throw ex;
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        }
    }

    private static boolean enviarConfirmacaoDesbloqueio(
            String destinatario,
            String remetente,
            Locale locale
    ) throws Exception {
        if (!Core.hasOutputSMTP()) {
            return false;
        } else if (!Core.hasAdminEmail()) {
            return false;
        } else if (!isValidEmail(remetente)) {
            return false;
        } else if (NoReply.isUnsubscribed(remetente)) {
            return false;
        } else {
            InternetAddress[] recipients = InternetAddress.parse(remetente);
            Document templateHTML;
            File logoFile;
            String subjectLocal;
            Element linkRecipient;
            if ((logoFile = Core.getLogoFile(null)) == null) {
                Server.logError("relased warning failed: logo.png not found");
                return false;
            } else if ((templateHTML = Core.getTemplateWarningReleasedSender(locale)) == null) {
                Server.logError("relased warning failed: warning.released.sender.en.html not found");
                return false;
            } else if ((subjectLocal = templateHTML.getElementsByTag("title").text()) == null) {
                Server.logError("relased warning failed: HTML title not found");
                return false;
            } else if ((linkRecipient = templateHTML.getElementById("recipient")) == null) {
                return false;
            } else {
                linkRecipient.attr("href", "mailto:" + destinatario);
                linkRecipient.text(destinatario);
                templateHTML = templateHTML.normalise();

                MimeMessage message = Core.newMessage(false);
                message.addRecipients(Message.RecipientType.TO, recipients);
                message.setReplyTo(InternetAddress.parse(destinatario));
                message.setSubject(subjectLocal);
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
        }
    }

    private static final HashMap<String,Object> sentUnblockConfirmationSMTP = new HashMap<>();

    private static String enviarConfirmacaoDesbloqueio(
            boolean secured,
            final String command,
            final String destinatario,
            final String remetente,
            final Locale locale
    ) {
        StringBuilder builder = new StringBuilder();
        Object resultSentSMTP = sentUnblockConfirmationSMTP.get(command);
        builder.append("<!DOCTYPE html>\n");
        builder.append("<html lang=\"");
        builder.append(locale.getLanguage());
        builder.append("\">\n");
        String title;
        String message;
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            title = "Página de desbloqueio de remetente";
            message = "Remetente desbloqueado com sucesso";
        } else {
            title = "Sender unblock page";
            message = "Sender successfully unlocked";
        }
        if (resultSentSMTP == null) {
            if (sentUnblockConfirmationSMTP.containsKey(command)) {
                buildHead(builder, title, Core.getURL(secured, locale, command), 5);
            } else {
                sentUnblockConfirmationSMTP.put(command, null);
                buildHead(builder, title, Core.getURL(secured, locale, command), 10);
                new Thread() {
                    @Override
                    public void run() {
                        try {
                            Thread.currentThread().setName("BCKGROUND");
                            sentUnblockConfirmationSMTP.put(command, enviarConfirmacaoDesbloqueio(destinatario, remetente, locale));
                        } catch (Exception ex) {
                            sentUnblockConfirmationSMTP.put(command, ex);
                        }
                    }
                }.start();
            }
        } else {
            buildHead(false, builder, title);
        }
        builder.append("  <body>\n");
        builder.append("    <div id=\"container\">\n");
        if (resultSentSMTP == null) {
            buildProcessing(builder);
            buildMessage(builder, message);
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "Estamos enviando a confirmação de desbloqueio ao remetente. Aguarde...");
            } else {
                buildText(builder, "We're sending the unblock confirmation to the sender. Wait...");
            }
        } else if (resultSentSMTP instanceof Boolean) {
            buildLogo(builder);
            buildMessage(builder, message);
            sentUnblockConfirmationSMTP.remove(command);
            boolean isSentSMTP = (Boolean) resultSentSMTP;
            if (isSentSMTP) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Confirmação de desbloqueio enviada com sucesso para " + remetente + ".");
                    buildText(builder, "Por favor, aguarde pelo reenvio das mensagens rejeitadas anteriormente.");
                } else {
                    buildText(builder, "Unblock confirmation sent successfully to " + remetente + ".");
                    buildText(builder, "Please, wait for the previously rejected messages to be resent.");
                }
            } else {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Não foi possível eviar a confirmação de desbloqueio para " + remetente + " devido a uma falha de sistema.");
                    buildText(builder, "Por favor, utilize outros meios de comunicação para informar o remetente para reenviar sua última mensagem.");
                } else {
                    buildText(builder, "Unable to send unlock confirmation to " + remetente + " due to system crash.");
                    buildText(builder, "Please, use other media to inform the sender to resend his last message.");
                }
            }
        } else if (resultSentSMTP instanceof SMTPAddressFailedException) {
            buildLogo(builder);
            buildMessage(builder, message);
            sentUnblockConfirmationSMTP.remove(command);
            SMTPAddressFailedException afex = (SMTPAddressFailedException) resultSentSMTP;
            if (afex.getReturnCode() == 551 || afex.getMessage().contains(" 5.1.1 ")) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "A confirmação de desbloqueio não pode ser enviada para " + remetente + " porque este endereço não existe.");
                    buildText(builder, "Por favor, utilize outros meios de comunicação para informar o remetente para reenviar sua última mensagem.");
                } else {
                    buildText(builder, "The unblock confirmation can not be sent to " + remetente + " because this address does not exist.");
                    buildText(builder, "Please, use other media to inform the sender to resend his last message.");
                }
            } else {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "A confirmação de desbloqueio não pode ser enviada para " + remetente + " devido a recusa do servidor do remetente.");
                    buildText(builder, "Por favor, utilize outros meios de comunicação para informar o remetente para reenviar sua última mensagem.");
                } else {
                    buildText(builder, "The unblock confirmation can not be sent to " + remetente + " due to denial of the sender's server.");
                    buildText(builder, "Please, use other media to inform the sender to resend his last message.");
                }
            }
        } else if (resultSentSMTP instanceof SendFailedException) {
            buildLogo(builder);
            buildMessage(builder, message);
            sentUnblockConfirmationSMTP.remove(command);
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "A confirmação de desbloqueio não pode ser enviada para " + remetente + " devido a recusa do servidor do remetente.");
                buildText(builder, "Por favor, utilize outros meios de comunicação para informar o remetente para reenviar sua última mensagem.");
            } else {
                buildText(builder, "The unblock confirmation can not be sent to " + remetente + " due to denial of the sender's server.");
                buildText(builder, "Please, use other media to inform the sender to resend his last message.");
            }
        } else if (resultSentSMTP instanceof NameNotFoundException) {
            buildLogo(builder);
            buildMessage(builder, message);
            sentUnblockConfirmationSMTP.remove(command);
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "A confirmação de desbloqueio não pode ser enviada para " + remetente + " porque o servidor do remetente não pode ser encontrado.");
                buildText(builder, "Por favor, utilize outros meios de comunicação para informar o remetente para reenviar sua última mensagem.");
            } else {
                buildText(builder, "The unblock confirmation can not be sent to " + remetente + " because the sender's server can not be found.");
                buildText(builder, "Please, use other media to inform the sender to resend his last message.");
            }
        } else if (resultSentSMTP instanceof MailConnectException) {
            buildLogo(builder);
            buildMessage(builder, message);
            sentUnblockConfirmationSMTP.remove(command);
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "A confirmação de desbloqueio não pode ser enviada para " + remetente + " porque o servidor do remetente se encontra indisponível.");
                buildText(builder, "Por favor, utilize outros meios de comunicação para informar o remetente para reenviar sua última mensagem.");
            } else {
                buildText(builder, "The unblocking confirmation can not be sent to " + remetente + " because the sender's server is unavailable.");
                buildText(builder, "Please, use other media to inform the sender to resend his last message.");
            }
        } else if (resultSentSMTP instanceof SocketConnectException) {
            buildLogo(builder);
            buildMessage(builder, message);
            sentUnblockConfirmationSMTP.remove(command);
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "A confirmação de desbloqueio não pode ser enviada para " + remetente + " pois o servidor do remetente está recusando nossa conexão SMTP.");
                buildText(builder, "Por favor, utilize outros meios de comunicação para informar o remetente para reenviar sua última mensagem.");
            } else {
                buildText(builder, "The unblock confirmation can not be sent to " + remetente + " because the sender's server is refusing our SMTP connection.");
                buildText(builder, "Please, use other media to inform the sender to resend his last message.");
            }
        } else if (resultSentSMTP instanceof SocketTimeoutException) {
            buildLogo(builder);
            buildMessage(builder, message);
            sentUnblockConfirmationSMTP.remove(command);
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "A confirmação de desbloqueio não pode ser enviada para " + remetente + " pois o servidor do remetente está demorando a responder.");
                buildText(builder, "Por favor, utilize outros meios de comunicação para informar o remetente para reenviar sua última mensagem.");
            } else {
                buildText(builder, "The unblock confirmation can not be sent to " + remetente + " because the sender's server is slow to respond.");
                buildText(builder, "Please, use other media to inform the sender to resend his last message.");
            }
        } else if (resultSentSMTP instanceof MessagingException) {
            buildLogo(builder);
            buildMessage(builder, message);
            sentUnblockConfirmationSMTP.remove(command);
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "A confirmação de desbloqueio não pode ser enviada para " + remetente + " pois o servidor do remetente está recusando nossa mensagem.");
                buildText(builder, "Por favor, utilize outros meios de comunicação para informar o remetente para reenviar sua última mensagem.");
            } else {
                buildText(builder, "The unblock confirmation can not be sent to " + remetente + " because the sender's server is declining our message.");
                buildText(builder, "Please, use other media to inform the sender to resend his last message.");
            }
        } else {
            buildLogo(builder);
            buildMessage(builder, message);
            sentUnblockConfirmationSMTP.remove(command);
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "Não foi possível enviar a confirmação de desbloqueio para " + remetente + " devido a uma falha do nosso sistema.");
                buildText(builder, "Por favor, utilize outros meios de comunicação para informar o remetente para reenviar sua última mensagem.");
            } else {
                buildText(builder, "Unable to send unblock confirmation to " + remetente + " due to a crash in our system.");
                buildText(builder, "Please, use other media to inform the sender to resend his last message.");
            }
        }
        buildFooter(builder, locale, null);
        builder.append("    </div>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private String getUnblockHMTL(
            Locale locale,
            String text
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<!DOCTYPE html>\n");
        builder.append("<html lang=\"");
        builder.append(locale.getLanguage());
        builder.append("\">\n");
        String title;
        String message;
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            title = "Página de desbloqueio do SPFBL";
            message = "A sua mensagem está sendo rejeitada por bloqueio manual";
        } else {
            title = "SPFBL unlock page";
            message = "Your message is being rejected by manual block";
        }
        buildHead(true, builder, title);
        builder.append("  <body>\n");
        builder.append("    <div id=\"container\">\n");
        buildLogo(builder);
        buildMessage(builder, message);
        buildText(builder, text);
        builder.append("      <div id=\"divcaptcha\">\n");
        builder.append("        <form method=\"POST\">\n");
        buildCaptcha(true, builder);
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("           <input id=\"btngo\" type=\"submit\" value=\"Solicitar\">\n");
        } else {
            builder.append("           <input id=\"btngo\" type=\"submit\" value=\"Request\">\n");
        }
        builder.append("        </form>\n");
        builder.append("      </div>\n");
        buildFooter(builder, locale, null);
        builder.append("    </div>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private String getUnblockDNSBLHMTL(
            Locale locale,
            String text
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<!DOCTYPE html>\n");
        builder.append("<html lang=\"");
        builder.append(locale.getLanguage());
        builder.append("\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            buildHead(true, builder, "Página de desbloqueio DNSBL");
        } else {
            buildHead(true, builder, "DNSBL unblock page");
        }
        builder.append("  <body>\n");
        builder.append("    <div id=\"container\">\n");
        buildAdvertise(builder);
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            buildMessage(builder, "Página de desbloqueio DNSBL");
        } else {
            buildMessage(builder, "DNSBL unblock page");
        }
        buildText(builder, text);
        builder.append("      <div id=\"divcaptcha\">\n");
        builder.append("        <form method=\"POST\">\n");
        buildCaptcha(true, builder);
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("           <input id=\"btngo\" type=\"submit\" value=\"Desbloquear\">\n");
        } else {
            builder.append("           <input id=\"btngo\" type=\"submit\" value=\"Unblock\">\n");
        }
        builder.append("        </form>\n");
        builder.append("      </div>\n");
        buildFooter(builder, locale, null);
        builder.append("    </div>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private String getWhiteHMTL(
            Locale locale,
            String text
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<!DOCTYPE html>\n");
        builder.append("<html lang=\"");
        builder.append(locale.getLanguage());
        builder.append("\">\n");
        String title;
        String message;
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            title = "Página de desbloqueio do SPFBL";
            message = "Este remetente foi bloqueado no sistema SPFBL";
        } else {
            title = "SPFBL unblock page";
            message = "The sender has been blocked in SPFBL system";

        }
        buildHead(false, builder, title);
        builder.append("  <body>\n");
        builder.append("    <div id=\"container\">\n");
        buildLogo(builder);
        buildMessage(builder, message);
        buildText(builder, text);
        builder.append("      <div id=\"divcaptcha\">\n");
        builder.append("        <form method=\"POST\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("           <input id=\"btngo\" type=\"submit\" value=\"Liberar\">\n");
        } else {
            builder.append("           <input id=\"btngo\" type=\"submit\" value=\"Release\">\n");
        }
        builder.append("        </form>\n");
        builder.append("      </div>\n");
        buildFooter(builder, locale, null);
        builder.append("    </div>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }
    
    private static String getLoginPasswordHMTL(
            Locale locale,
            String message,
            String text
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<!DOCTYPE html>\n");
        builder.append("<html lang=\"");
        builder.append(locale.getLanguage());
        builder.append("\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            buildHead(true, builder, "Página de login do SPFBL");
        } else {
            buildHead(true, builder, "SPFBL login page");
        }
        builder.append("  <body>\n");
        builder.append("    <div id=\"container\">\n");
        buildLogo(builder);
        buildMessage(builder, message);
        buildText(builder, text);
        builder.append("      <div id=\"divcaptcha\">\n");
        builder.append("        <form method=\"POST\">\n");
        builder.append("          <input type=\"password\" name=\"password\" autofocus><br>\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("           <input id=\"btngo\" type=\"submit\" value=\"Entrar\">\n");
        } else {
            builder.append("           <input id=\"btngo\" type=\"submit\" value=\"Login\">\n");
        }
        builder.append("        </form>\n");
        builder.append("      </div>\n");
        buildFooter(builder, locale, null);
        builder.append("    </div>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private static String getLoginOTPHMTL(
            Locale locale,
            String message,
            String text
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<!DOCTYPE html>\n");
        builder.append("<html lang=\"");
        builder.append(locale.getLanguage());
        builder.append("\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            buildHead(true, builder, "Página de login do SPFBL");
        } else {
            buildHead(true, builder, "SPFBL login page");
        }
        builder.append("  <body>\n");
        builder.append("    <div id=\"container\">\n");
        buildLogo(builder);
        buildMessage(builder, message);
        buildText(builder, text);
        builder.append("      <div id=\"divcaptcha\">\n");
        builder.append("        <form method=\"POST\">\n");
        builder.append("          <input type=\"password\" name=\"otp\" autofocus><br>\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("           <input id=\"btngo\" type=\"submit\" value=\"Entrar\">\n");
        } else {
            builder.append("           <input id=\"btngo\" type=\"submit\" value=\"Login\">\n");
        }
        builder.append("        </form>\n");
        builder.append("      </div>\n");
        buildFooter(builder, locale, null);
        builder.append("    </div>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private String getSendOTPHMTL(
            Locale locale,
            String message,
            String text
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<!DOCTYPE html>\n");
        builder.append("<html lang=\"");
        builder.append(locale.getLanguage());
        builder.append("\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            buildHead(true, builder, "Página de login do SPFBL");
        } else {
            buildHead(true, builder, "SPFBL login page");
        }
        builder.append("  <body>\n");
        builder.append("    <div id=\"container\">\n");
        buildLogo(builder);
        buildMessage(builder, message);
        buildText(builder, text);
        builder.append("      <div id=\"divcaptcha\">\n");
        builder.append("        <form method=\"POST\">\n");
        buildCaptcha(true, builder);
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("           <input id=\"btngo\" type=\"submit\" value=\"Enviar\">\n");
        } else {
            builder.append("           <input id=\"btngo\" type=\"submit\" value=\"Send\">\n");
        }
        builder.append("        </form>\n");
        builder.append("      </div>\n");
        buildFooter(builder, locale, null);
        builder.append("    </div>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private String getReleaseHMTL(
            Locale locale,
            String text
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<!DOCTYPE html>\n");
        builder.append("<html lang=\"");
        builder.append(locale.getLanguage());
        builder.append("\">\n");
        String title;
        String message;
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            title = "Página de liberação SPFBL";
            message = "O recebimento da sua mensagem está sendo atrasado por suspeita de SPAM";
        } else {
            title = "SPFBL release page";
            message = "The receipt of your message is being delayed by SPAM suspect";
        }
        buildHead(true, builder, title);
        builder.append("  <body>\n");
        builder.append("    <div id=\"container\">\n");
        buildLogo(builder);
        buildMessage(builder, message);
        buildText(builder, text);
        builder.append("      <div id=\"divcaptcha\">\n");
        builder.append("        <form method=\"POST\">\n");
        buildCaptcha(true, builder);
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("           <input id=\"btngo\" type=\"submit\" value=\"Liberar\">\n");
        } else {
            builder.append("           <input id=\"btngo\" type=\"submit\" value=\"Release\">\n");
        }
        builder.append("        </form>\n");
        builder.append("      </div>\n");
        buildFooter(builder, locale, null);
        builder.append("    </div>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private String getRequestHoldHMTL(
            Locale locale,
            String text
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<!DOCTYPE html>\n");
        builder.append("<html lang=\"");
        builder.append(locale.getLanguage());
        builder.append("\">\n");
        String title;
        String message;
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            title = "Página de liberação SPFBL";
            message = "A mensagem retida por suspeita de SPAM";
        } else {
            title = "SPFBL release page";
            message = "The message retained on suspicion of SPAM";
        }
        buildHead(true, builder, title);
        builder.append("  <body>\n");
        builder.append("    <div id=\"container\">\n");
        buildLogo(builder);
        buildMessage(builder, message);
        buildText(builder, text);
        builder.append("      <div id=\"divcaptcha\">\n");
        builder.append("        <form method=\"POST\">\n");
        buildCaptcha(true, builder);
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("           <input id=\"btngo\" type=\"submit\" value=\"Solicitar\">\n");
        } else {
            builder.append("           <input id=\"btngo\" type=\"submit\" value=\"Request\">\n");
        }
        builder.append("        </form>\n");
        builder.append("      </div>\n");
        buildFooter(builder, locale, null);
        builder.append("    </div>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private String getReleaseHoldHMTL(
            Locale locale,
            String text
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<!DOCTYPE html>\n");
        builder.append("<html lang=\"");
        builder.append(locale.getLanguage());
        builder.append("\">\n");
        String title;
        String message;
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            title = "Página de liberação SPFBL";
            message = "A mensagem retida por suspeita de SPAM";
        } else {
            title = "SPFBL release page";
            message = "The message retained on suspicion of SPAM";
        }
        buildHead(false, builder, title);
        builder.append("  <body>\n");
        builder.append("    <div id=\"container\">\n");
        buildLogo(builder);
        buildMessage(builder, message);
        buildText(builder, text);
        builder.append("      <div id=\"divcaptcha\">\n");
        builder.append("        <form method=\"POST\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("           <input id=\"btngo\" type=\"submit\" value=\"Liberar\">\n");
        } else {
            builder.append("           <input id=\"btngo\" type=\"submit\" value=\"Release\">\n");
        }
        builder.append("        </form>\n");
        builder.append("      </div>\n");
        buildFooter(builder, locale, null);
        builder.append("    </div>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private String getBlockHMTL(
            Locale locale,
            String message,
            String text
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<!DOCTYPE html>\n");
        builder.append("<html lang=\"");
        builder.append(locale.getLanguage());
        builder.append("\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            buildHead(false, builder, "Página de bloqueio SPFBL");
        } else {
            buildHead(false, builder, "SPFBL block page");
        }
        builder.append("  <body>\n");
        builder.append("    <div id=\"container\">\n");
        buildLogo(builder);
        buildMessage(builder, message);
        buildText(builder, text);
        builder.append("      <div id=\"divcaptcha\">\n");
        builder.append("        <form method=\"POST\">\n");
        buildCaptcha(true, builder);
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("           <input id=\"btngo\" type=\"submit\" value=\"Bloquear\">\n");
        } else {
            builder.append("           <input id=\"btngo\" type=\"submit\" value=\"Block\">\n");
        }
        builder.append("        </form>\n");
        builder.append("      </div>\n");
        buildFooter(builder, locale, null);
        builder.append("    </div>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private String getUnsubscribeHMTL(
            Locale locale,
            String message,
            String text
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<!DOCTYPE html>\n");
        builder.append("<html lang=\"");
        builder.append(locale.getLanguage());
        builder.append("\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            buildHead(true, builder, "Página de cancelamento SPFBL");
        } else {
            buildHead(true, builder, "SPFBL unsubscribe page");
        }
        builder.append("  <body>\n");
        builder.append("    <div id=\"container\">\n");
        buildLogo(builder);
        buildMessage(builder, message);
        buildText(builder, text);
        builder.append("      <div id=\"divcaptcha\">\n");
        builder.append("        <form method=\"POST\">\n");
        buildCaptcha(false, builder);
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("           <input id=\"btngo\" type=\"submit\" value=\"Desinscrever\">\n");
        } else {
            builder.append("           <input id=\"btngo\" type=\"submit\" value=\"Unsubscribe\">\n");
        }
        builder.append("        </form>\n");
        builder.append("      </div>\n");
        buildFooter(builder, locale, null);
        builder.append("    </div>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private static String getRedirectHMTL(
            Locale locale,
            String title,
            String message,
            String page,
            int time
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<!DOCTYPE html>\n");
        builder.append("<html lang=\"");
        builder.append(locale.getLanguage());
        builder.append("\">\n");
        buildHead(builder, title, page, time);
        builder.append("  <body>\n");
        builder.append("    <div id=\"container\">\n");
        buildLogo(builder);
        buildMessage(builder, message);
        buildFooter(builder, locale, null);
        builder.append("    </div>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private static String getMessageHMTL(
            Locale locale,
            String title,
            String message
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<!DOCTYPE html>\n");
        builder.append("<html lang=\"");
        builder.append(locale.getLanguage());
        builder.append("\">\n");
        buildHead(false, builder, title);
        builder.append("  <body>\n");
        builder.append("    <div id=\"container\">\n");
        buildLogo(builder);
        buildMessage(builder, title);
        buildText(builder, message);
        buildFooter(builder, locale, null);
        builder.append("    </div>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private static TreeSet<String> getPostmaterSet(String query) {
        TreeSet<String> emailSet = new TreeSet<>();
        if (isValidIP(query)) {
            String ip = Subnet.normalizeIP(query);
            String fqdn = FQDN.getFQDN(ip, false);
            TreeSet<String> reverseSet;
            if (fqdn == null) {
                reverseSet = Reverse.getPointerSetSafe(ip);
            } else {
                reverseSet = new TreeSet<>();
                reverseSet.add(fqdn);
                String hostname = Reverse.getValidHostname(ip);
                String domain = Domain.extractDomainSafe(hostname, false);
                if (domain != null) {
                    emailSet.add("postmaster@" + domain);
                }
            }
            if (!reverseSet.isEmpty()) {
                String hostname = reverseSet.pollFirst();
                do {
                    hostname = Domain.normalizeHostname(hostname, true);
                    if (
                            !hostname.endsWith(".arpa") &&
                            !Generic.isGenericEC2(hostname) &&
                            !NoReply.containsTLD(hostname) &&
                            !NoReply.containsDomain(hostname)
                            ) {
                        String domain;
                        try {
                            domain = Domain.extractDomain(hostname, true);
                        } catch (ProcessException ex) {
                            domain = null;
                        }
                        if (domain != null) {
                            String email = "postmaster@" + domain.substring(1);
                            if (!NoReply.contains(email, true)) {
                                emailSet.add(email);
                            }
                            if (fqdn != null) {
                                email = "abuse@" + domain.substring(1);
                                if (!NoReply.contains(email, true)) {
                                    emailSet.add(email);
                                }
                            }
                            String abuseSource = Abuse.getEmailIP(ip);
                            if (Abuse.isSubscribed(abuseSource)) {
                                emailSet.add(abuseSource);
                            }
                            boolean fcrdnsValid = Reverse.getAddressSetSafe(hostname).contains(ip);
                            if (fcrdnsValid) {
                                String abuseDomain = Abuse.getEmailFQDN(hostname);
                                if (Abuse.isSubscribed(abuseDomain)) {
                                    emailSet.add(abuseDomain);
                                }
                            }
                            if (fcrdnsValid && fqdn == null && !Generic.containsGeneric(hostname)) {
                                String subdominio = hostname;
                                while (!subdominio.equals(domain)) {
                                    email = "postmaster@" + subdominio.substring(1);
                                    if (!NoReply.contains(email, true)) {
                                        emailSet.add(email);
                                    }
                                    int index = subdominio.indexOf('.', 1);
                                    subdominio = subdominio.substring(index);
                                }
                                
                            }
                        }
                    }
                } while ((hostname = reverseSet.pollFirst()) != null);
            }
        } else if (isHostname(query)) {
            String hostname = Domain.normalizeHostname(query, false);
            String domain;
            try {
                domain = Domain.extractDomain(hostname, false);
            } catch (ProcessException ex) {
                domain = null;
            }
            if (domain != null) {
                String subdominio = hostname;
                while (subdominio.endsWith(domain)) {
                    String email = "postmaster@" + subdominio;
                    if (!NoReply.contains(email, true)) {
                        emailSet.add(email);
                    }
                    int index = subdominio.indexOf('.', 1) + 1;
                    subdominio = subdominio.substring(index);
                }
            }
        }
        return emailSet;
    }

    private static final HashMap<String, Boolean> openSMTP = new HashMap<>();
    private static final HashMap<String, String> checkURL = new HashMap<>();

    private String getDNSBLHTML(
            boolean secured,
            HashMap<String, Object> parameterMap,
            Locale locale,
            User user,
            Client client,
            final String query,
            String message
    ) {
        StringBuilder builder = new StringBuilder();
        boolean processing = false;
        boolean isSLAAC = SubnetIPv6.isSLAAC(query) && !Subnet.isReservedIP(query);
        String fqdn = FQDN.getFQDN(query, false);
        Boolean isOpenSMTP = openSMTP.get(query);
        String urlResult = checkURL.get(query);
        builder.append("<!DOCTYPE html>\n");
        builder.append("<html lang=\"");
        builder.append(locale.getLanguage());
        builder.append("\">\n");
        String tecnology = Core.isValidURL(query) ? "URIBL" : "DNSBL";
        String title;
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            title = "Página de checagem " + tecnology;
        } else {
            title = tecnology + " check page";
        }
        if (isSLAAC && fqdn == null && isOpenSMTP == null) {
            processing = true;
            if (openSMTP.containsKey(query)) {
                buildHead(builder, title, "/" + locale.getLanguage() + "/" + query, 5);
            } else {
                buildHead(builder, title, "/" + locale.getLanguage() + "/" + query, 10);
                openSMTP.put(query, null);
                new Thread() {
                    @Override
                    public void run() {
                        Thread.currentThread().setName("BCKGROUND");
                        openSMTP.put(query, Analise.isOpenSMTP(query, 30000, 25, 587));
                    }
                }.start();
            }
        } else if (urlResult == null && isSignatureURL(query)) {
            String urlString = Core.decompressAsStringSafe(query);
            String signature1 = Core.getSignatureURL(urlString);
            if (Block.containsSignatureBlockURL(signature1)) {
                urlResult = "BLOCKED";
                buildHead(true, builder, title);
            } else {
                processing = true;
                if (checkURL.containsKey(query)) {
                    buildHead(builder, title, "/" + locale.getLanguage() + "/" + query, 5);
                } else {
                    buildHead(builder, title, "/" + locale.getLanguage() + "/" + query, 10);
                    checkURL.put(query, null);
                    new Thread() {
                        @Override
                        public void run() {
                            try {
                                Thread.currentThread().setName("BCKGROUND");
                                String nextURL = urlString;
                                TreeSet<String> processedSet = new TreeSet<>();
                                while (processedSet.add(nextURL) && processedSet.size() < 256) {
                                    URL url = new URL(nextURL);
                                    if (url.getProtocol().equals("mailto")) {
                                        String email = url.getPath();
                                        if (Block.containsHREF(email)) {
                                            for (String link : processedSet) {
                                                String signatureURL = Core.getSignatureURL(link);
                                                if (Block.addExact(signatureURL)) {
                                                    Server.logDebug(null, "new BLOCK '" + signatureURL + "' added by 'HREF=" + email + "'.");
                                                }
                                            }
                                            checkURL.put(query, "BLOCKED");
                                        }
                                        break;
                                    } else {
                                        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                                        conn.setConnectTimeout(5000);
                                        conn.setReadTimeout(10000);
                                        conn.addRequestProperty("Accept-Language", locale.toLanguageTag() + "," + locale.getLanguage() + ";q=0.8");
                                        conn.addRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0");
                                        conn.setInstanceFollowRedirects(false);
                                        int code = conn.getResponseCode();
                                        if (code == 200) {
                                            int length = conn.getContentLength();
                                            if (length < 1048576) {
                                                String type = conn.getContentType();
                                                StringTokenizer tokenizer = new StringTokenizer(type, ";");
                                                type = tokenizer.nextToken().trim();
                                                if (type.startsWith("application/")) {
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
                                                                String signatureFile = md5 + "." + length + "." + extension;
                                                                Server.logWarning("executable download found: " + signatureFile);
                                                                if (Block.containsExact(signatureFile)) {
                                                                    for (String link : processedSet) {
                                                                        String signatureURL = Core.getSignatureURL(link);
                                                                        if (Block.addExact(signatureURL)) {
                                                                            Server.logDebug(null, "new BLOCK '" + signatureURL + "' added by '" + signatureFile + "'.");
                                                                        }
                                                                    }
                                                                    checkURL.put(query, "EXECUTABLE");
                                                                }
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
                                                            Server.logWarning("executable download found: " + signatureFile);
                                                            if (Block.containsExact(signatureFile)) {
                                                                for (String link : processedSet) {
                                                                    String signatureURL = Core.getSignatureURL(link);
                                                                    if (Block.addExact(signatureURL)) {
                                                                        Server.logDebug(null, "new BLOCK '" + signatureURL + "' added by '" + signatureFile + "'.");
                                                                    }
                                                                }
                                                                checkURL.put(query, "EXECUTABLE");
                                                            }
                                                        } else if (Core.COMPACTED_SET.contains(extension)) {
                                                            // TODO: implement decompression algorithm.
                                                            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                                                            try (InputStream inputStream = conn.getInputStream()) {
                                                                while ((code = inputStream.read()) != -1) {
                                                                    messageDigest.update((byte) code);
                                                                }
                                                            }
                                                            String md5 = Core.md5Hex(messageDigest.digest());
                                                            String signatureFile = md5 + "." + length + "." + extension;
                                                            Server.logWarning("compacted download found: " + signatureFile);
                                                            if (Block.containsExact(signatureFile)) {
                                                                for (String link : processedSet) {
                                                                    String signatureURL = Core.getSignatureURL(link);
                                                                    if (Block.addExact(signatureURL)) {
                                                                        Server.logDebug(null, "new BLOCK '" + signatureURL + "' added by '" + signatureFile + "'.");
                                                                    }
                                                                }
                                                                checkURL.put(query, "EXECUTABLE");
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            break;
                                        } else if (code == HttpURLConnection.HTTP_MOVED_TEMP
                                                || code == HttpURLConnection.HTTP_MOVED_PERM
                                                || code == HttpURLConnection.HTTP_SEE_OTHER) {
                                            String location = conn.getHeaderField("Location");
                                            try {
                                                nextURL = URLDecoder.decode(location, "UTF-8");
                                                if (nextURL.contains(":")) {
                                                    url = new URL(nextURL);
                                                } else {
                                                    url = new URL(url, nextURL);
                                                    nextURL = url.toString();
                                                }
                                                String signatureLocation = Core.getSignatureURL(nextURL);
                                                if (Block.containsSignatureBlockURL(signatureLocation)) {
                                                    for (String link : processedSet) {
                                                        String signatureURL = Core.getSignatureURL(link);
                                                        if (Block.addExact(signatureURL)) {
                                                            Server.logDebug(null, "new BLOCK '" + signatureURL + "' added by '" + signatureLocation + "'.");
                                                        }
                                                    }
                                                    checkURL.put(query, "HIDDEN");
                                                } else if (Core.SHORTENER_SET.contains(url.getHost().toLowerCase())) {
                                                    for (String link : processedSet) {
                                                        String signatureURL = Core.getSignatureURL(link);
                                                        if (Block.addExact(signatureURL)) {
                                                            Server.logDebug(null, "new BLOCK '" + signatureURL + "' added by 'SPFBL.Shortener.evasion'.");
                                                        }
                                                    }
                                                    checkURL.put(query, "DOUBLE");
                                                }
                                            } catch (MalformedURLException ex) {
                                                checkURL.put(query, "ERROR");
                                                break;
                                            }
                                        }
                                    }
                                }
                                if (checkURL.get(query) == null) {
                                    String threat = Core.checkGoogleSafeBrowsing(null, null, processedSet);
                                    if (threat == null) {
                                        checkURL.put(query, "NONE");
                                    } else {
                                        for (String link : processedSet) {
                                            String signatureURL = Core.getSignatureURL(link);
                                            if (Block.addExact(signatureURL)) {
                                                Server.logDebug(null, "new BLOCK '" + signatureURL + "' added by '" + threat + "'.");
                                            }
                                        }
                                        checkURL.put(query, "THREAT");
                                    }
                                }
                            } catch (NoRouteToHostException ex) {
                                checkURL.put(query, "ERROR");
                            } catch (ConnectException ex) {
                                checkURL.put(query, "TIMEOUT");
                            } catch (SocketException ex) {
                                checkURL.put(query, "ERROR");
                            } catch (UnknownHostException ex) {
                                checkURL.put(query, "NXDOMAIN");
                            } catch (SocketTimeoutException ex) {
                                checkURL.put(query, "TIMEOUT");
                            } catch (SSLHandshakeException ex) {
                                checkURL.put(query, "ERROR");
                            } catch (SSLException ex) {
                                checkURL.put(query, "ERROR");
                            } catch (Exception ex) {
                                Server.logError(ex);
                                checkURL.put(query, "ERROR");
                            }
                        }
                    }.start();
                }
            }
        } else {
            buildHead(true, builder, title);
        }
        builder.append("  <body>\n");
        builder.append("    <div id=\"container\">\n");
        if (processing) {
            buildProcessing(builder);
        } else {
            buildAdvertise(builder);
        }
        buildMessage(builder, locale, message);
        TreeMap<String, Boolean> emailMap = new TreeMap<>();
        if (isValidIP(query)) {
            String ip = Subnet.normalizeIP(query);
            ip = SubnetIPv6.tryTransformToIPv4(ip);
            if (Subnet.isReservedIP(ip)) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Este é um IP reservado e por este motivo não é abordado nesta lista.");
                } else {
                    buildText(builder, "This is a reserved IP and for this reason is not addressed in this list.");
                }
            } else if (isSLAAC && fqdn == null && isOpenSMTP == null) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Este IP contém sinalização de autoconfiguração de endereço de rede (SLAAC).");
                    buildText(builder, "Estamos verificando se existe serviço SMTP neste IP a fim de descartar dispositos IoT. Aguarde...");
                } else {
                    buildText(builder, "This IP contains network address autoconfiguration flag (SLAAC).");
                    buildText(builder, "We are checking if there is SMTP service on this IP in order to discard IoT devices. Wait...");
                }
            } else if (isSLAAC && fqdn == null && !isOpenSMTP) {
                openSMTP.remove(query);
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Este IP contém sinalização de autoconfiguração de endereço de rede (SLAAC) mas não foi possível verificar se existe um serviço de e-mail válido nele.");
                    buildText(builder, "Se este IP está sendo usado por um servidor de e-mail legítimo, abra a porta 25 para que possamos verificar que existe um serviço SMTP nele.");
                } else {
                    buildText(builder, "This IP contains network address autoconfiguration flag (SLAAC) but it was not possible to verify that there is a valid email service on it.");
                    buildText(builder, "If this IP is being used by genuine email server, open port 25 so we can check that there is a SMTP service on it.");
                }
            } else {
                openSMTP.remove(query);
                boolean generic = false;
                boolean dynamic = false;
                boolean genericEC2 = false;
                boolean payment = false;
                String paypalUSD = Core.getPayPalPriceDelistUSD();
                String paypalEUR = Core.getPayPalPriceDelistEUR();
                String paypalJPY = Core.getPayPalPriceDelistJPY();
                String paypalBRL = Core.getPayPalPriceDelistBRL();
                Status reputationStatus = SPF.getStatus(ip, true);
                float reputationProbability = SPF.getSpamProbability(ip);
                fqdn = FQDN.discoverFQDN(ip);
                TreeSet<String> reverseSet;
                if (fqdn == null) {
                    reverseSet = Reverse.getPointerSetSafe(ip);
                    Block.tryToDominoBlockIP(ip, "INVALID");
                } else {
                    reverseSet = new TreeSet<>();
                    String hostname = Reverse.getValidHostname(ip);
                    String domain = Domain.extractDomainSafe(hostname, false);
                    if (domain != null) {
                        emailMap.put("postmaster@" + domain, true);
                    }
                    if (Ignore.containsIPorFQDN(ip)) {
                        Block.clearFQDN(null, fqdn, Core.getAdminEmail());
                        Block.clearCIDR(null, ip, Core.getAdminEmail());
                    } else if (Provider.containsIPorFQDN(ip)) {
                        Block.clearFQDN(null, fqdn, Core.getAdminEmail());
                        Block.clearCIDR(null, ip, Core.getAdminEmail());
                    } else if (White.containsFQDN(fqdn)) {
                        Block.clearFQDN(null, fqdn, Core.getAdminEmail());
                        Block.clearCIDR(null, ip, Core.getAdminEmail());
                    } else if (Block.containsFQDN(fqdn)) {
                        Block.tryToDominoBlockIP(ip, "BLOCK");
                    } else if (Abuse.containsSubscribedIP(ip)) {
                        SPF.Distribution dist = SPF.getDistribution(ip, false);
                        if (dist == null || dist.isGreen(ip)) {
                            Block.clearCIDR(null, ip, Core.getAdminEmail());
                        }
                    }
                }
                if (fqdn == null && reverseSet.isEmpty()) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        buildText(builder, "Nenhum <a target=\"_blank\" href=\"http://spfbl.net/rdns/\">rDNS</a> foi encontrado.");
                    } else {
                        buildText(builder, "No <a target=\"_blank\" href=\"http://spfbl.net/rdns/\">rDNS</a> was found.");
                    }
                } else {
                    if (fqdn != null) {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            buildText(builder, "Foi encontrado um servidor de e-mail rodando neste endereço:");
                        } else {
                            buildText(builder, "Found an email server running at this address:");
                        }
                    } else if (reverseSet.size() == 1) {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            buildText(builder, "Este é o <a target=\"_blank\" href=\"http://spfbl.net/rdns/\">rDNS</a> encontrado:");
                        } else {
                            buildText(builder, "This is the <a target=\"_blank\" href=\"http://spfbl.net/en/rdns/\">rDNS</a> found:");
                        }
                    } else {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            buildText(builder, "Estes são os <a target=\"_blank\" href=\"http://spfbl.net/rdns/\">rDNS</a> encontrados:");
                        } else {
                            buildText(builder, "These are the <a target=\"_blank\" href=\"http://spfbl.net/en/rdns/\">rDNS</a> found:");
                        }
                    }
                    String userEmail = user == null ? null : user.getEmail();
                    String abuseSource = Abuse.getEmailFQDN(fqdn);
                    builder.append("        <ul>\n");
                    String hostname;
                    if (fqdn == null) {
                        hostname = reverseSet.pollFirst();
                    } else {
                        hostname = fqdn;
                    }
                    long endTime = System.currentTimeMillis() + 30000;
                    do {
                        hostname = Domain.normalizeHostname(hostname, false);
                        String domain;
                        try {
                            domain = Domain.extractDomain(hostname, false);
                        } catch (ProcessException ex) {
                            domain = null;
                        }
                        builder.append("          <li>&lt;<a href=\"./");
                        builder.append(hostname);
                        builder.append("\">");
                        builder.append(hostname);
                        builder.append("</a>&gt; ");
                        if (domain == null || hostname.endsWith(".arpa")) {
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                builder.append("domínio reservado.</li>\n");
                            } else {
                                builder.append("reserved domain.</li>\n");
                            }
                        } else if (hostname.endsWith(".local")) {
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                builder.append("domínio local.</li>\n");
                            } else {
                                builder.append("local domain.</li>\n");
                            }
                        } else if (Generic.isGenericEC2(hostname)) {
                            genericEC2 = true;
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                builder.append("<a target=\"_blank\" href=\"http://spfbl.net/aws/\">EC2 genérico</a>.</li>\n");
                            } else {
                                builder.append("<a target=\"_blank\" href=\"http://spfbl.net/en/aws/\">generic EC2</a>.</li>\n");
                            }
                        } else if (Generic.containsDynamic(hostname)) {
                            dynamic = true;
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                builder.append("<a target=\"_blank\" href=\"http://spfbl.net/dynamic/\">rDNS dinâmico ou doméstico</a>.</li>\n");
                            } else {
                                builder.append("<a target=\"_blank\" href=\"http://spfbl.net/en/dynamic/\">dynamic or domestic rDNS</a>.</li>\n");
                            }
                        } else {
                            if (Block.containsFQDN(hostname)) {
                                Block.tryAdd(ip);
                            }
                            if (Abuse.isSubscribed(abuseSource)) {
                                emailMap.put(abuseSource, true);
                            }
                            try {
                                if (Generic.containsGeneric(domain)) {
                                    generic = true;
                                    if (Reverse.getAddressSetNotNull(hostname).contains(ip)) {
                                        emailMap.put("postmaster@" + domain, false);
                                    }
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        builder.append("domínio genérico.</li>\n");
                                    } else {
                                        builder.append("generic domain.</li>\n");
                                    }
                                } else if (Generic.containsGeneric(hostname)) {
                                    generic = true;
                                    if (Reverse.getAddressSetNotNull(hostname).contains(ip)) {
                                        emailMap.put("postmaster@" + domain, true);
                                    }
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        builder.append("<a target=\"_blank\" href=\"http://spfbl.net/generic/\">rDNS genérico</a>.</li>\n");
                                    } else {
                                        builder.append("<a target=\"_blank\" href=\"http://spfbl.net/en/generic/\">generic rDNS</a>.</li>\n");
                                    }
                                } else if (NoReply.containsTLD(hostname)) {
                                    payment = true;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        builder.append("TLD sem conformidade.</li>\n");
                                    } else {
                                        builder.append("non-compliance TLD.</li>\n");
                                    }
                                } else if (NoReply.containsDomain(hostname)) {
                                    payment = true;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        builder.append("domínio sem conformidade.</li>\n");
                                    } else {
                                        builder.append("non-compliance domain.</li>\n");
                                    }
                                } else if (hostname.equals(fqdn)) {
                                    emailMap.put("postmaster@" + domain, true);
                                    emailMap.put("abuse@" + domain, true);
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        builder.append("FQDN do serviço.</li>\n");
                                    } else {
                                        builder.append("service's FQDN.</li>\n");
                                    }
                                    Status reputationStatus2 = SPF.getStatus("." + hostname, true);
                                    float reputationProbability2 = SPF.getSpamProbability("." + hostname);
                                    if (reputationProbability2 > reputationProbability) {
                                        reputationStatus = reputationStatus2;
                                        reputationProbability = reputationProbability2;
                                    }
                                } else if (Reverse.getAddressSetNotNull(hostname).contains(ip)) {
                                    int loop = 0;
                                    String subdominio = hostname;
                                    while (loop++ < 32 && subdominio.endsWith(domain)) {
                                        String email = "postmaster@" + subdominio;
                                        emailMap.put(email, true);
                                        int index = subdominio.indexOf('.', 1) + 1;
                                        subdominio = subdominio.substring(index);
                                        if (NoReply.contains(email, false)) {
                                            payment = true;
                                        }
                                    }
                                    String abuseDomain = Abuse.getEmailFQDN(hostname);
                                    if (Abuse.isSubscribed(abuseDomain)) {
                                        emailMap.put(abuseDomain, true);
                                    }
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        builder.append("<a target=\"_blank\" href=\"http://spfbl.net/fcrdns/\">FCrDNS</a> válido.</li>\n");
                                    } else {
                                        builder.append("valid <a target=\"_blank\" href=\"http://spfbl.net/en/fcrdns/\">FCrDNS</a>.</li>\n");
                                    }
                                    Status reputationStatus2 = SPF.getStatus("." + hostname, true);
                                    float reputationProbability2 = SPF.getSpamProbability("." + hostname);
                                    if (reputationProbability2 > reputationProbability) {
                                        reputationStatus = reputationStatus2;
                                        reputationProbability = reputationProbability2;
                                    }
                                } else if (Ignore.containsFQDN(hostname)) {
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        builder.append("<a target=\"_blank\" href=\"http://spfbl.net/fcrdns/\">FCrDNS</a> inválido.</li>\n");
                                    } else {
                                        builder.append("invalid <a target=\"_blank\" href=\"http://spfbl.net/en/fcrdns/\">FCrDNS</a>.</li>\n");
                                    }
                                } else {
                                    payment = true;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        builder.append("<a target=\"_blank\" href=\"http://spfbl.net/fcrdns/\">FCrDNS</a> inválido.</li>\n");
                                    } else {
                                        builder.append("invalid <a target=\"_blank\" href=\"http://spfbl.net/en/fcrdns/\">FCrDNS</a>.</li>\n");
                                    }
                                }
                            } catch (NamingException ex) {
                                if (Generic.containsDynamic(hostname)) {
                                    dynamic = true;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        builder.append("<a target=\"_blank\" href=\"http://spfbl.net/dynamic/\">rDNS dinâmico ou doméstico</a>.</li>\n");
                                    } else {
                                        builder.append("<a target=\"_blank\" href=\"http://spfbl.net/en/dynamic/\">dynamic or domestic rDNS</a>.</li>\n");
                                    }
                                } else if (Generic.containsGeneric(hostname)) {
                                    generic = true;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        builder.append("<a target=\"_blank\" href=\"http://spfbl.net/generic/\">rDNS genérico</a>.</li>\n");
                                    } else {
                                        builder.append("<a target=\"_blank\" href=\"http://spfbl.net/en/generic/\">generic rDNS</a>.</li>\n");
                                    }
                                } else if (Provider.containsFQDN(hostname)) {
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        builder.append("domínio inexistente.</li>\n");
                                    } else {
                                        builder.append("non-existent domain.</li>\n");
                                    }
                                } else {
                                    payment = true;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        builder.append("domínio inexistente.</li>\n");
                                    } else {
                                        builder.append("non-existent domain.</li>\n");
                                    }
                                }
                            }
                        }
                    } while (System.currentTimeMillis() < endTime && (hostname = reverseSet.pollFirst()) != null);
                    builder.append("        </ul>\n");
                }
                if (payment) {
                    if (paypalUSD != null) {
                        emailMap.put("PAYPAL_USD_" + paypalUSD, true);
                    }
                    if (paypalEUR != null) {
                        emailMap.put("PAYPAL_EUR_" + paypalEUR, true);
                    }
                    if (paypalJPY != null) {
                        emailMap.put("PAYPAL_JPY_" + paypalJPY, true);
                    }
                    if (paypalBRL != null) {
                        emailMap.put("PAYPAL_BRL_" + paypalBRL, true);
                    }
                }
                if (dynamic) {
                    Block.tryToDominoBlockIP(ip, "DYNAMIC");
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        buildText(builder, "Este IP foi marcado por ser <a target=\"_blank\" href=\"http://spfbl.net/dynamic/\">dinâmico</a> ou por suspeita de uso exclusivamente doméstico.");
                        buildText(builder, "Se tiver rodando um serviço de e-mail neste IP, solicite a alteração do <a target=\"_blank\" href=\"http://spfbl.net/rdns/\">rDNS</a> ao ISP.");
                        buildText(builder, "A remoção deste IP nesta lista depende desta alteração do <a target=\"_blank\" href=\"http://spfbl.net/rdns/\">rDNS</a> de modo a ser igual ao FQDN do servidor de e-mail.");
                    } else {
                        buildText(builder, "This IP has been flagged because it is <a target=\"_blank\" href=\"http://spfbl.net/en/dynamic/\">dynamic</a> or by suspect to be domestic use only.");
                        buildText(builder, "If you are running an email service on this IP, ask ISP to change the <a target=\"_blank\" href=\"http://spfbl.net/en/rdns/\">rDNS</a>.");
                        buildText(builder, "The removal of this IP from this blacklist depends on change of <a target=\"_blank\" href=\"http://spfbl.net/en/rdns/\">rDNS</a> to match the FQDN of the mail server.");
                    }
                } else if (genericEC2 && Block.containsCIDR(ip)) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        buildText(builder, "Este IP foi marcado por ser um <a target=\"_blank\" href=\"http://spfbl.net/aws/\">EC2 genérico</a> sem um servidor de e-mail.");
                        buildText(builder, "Solicite um <a target=\"_blank\" href=\"https://docs.aws.amazon.com/pt_br/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html\">Elastic IP</a> à AWS, com a devida identificação no rDNS, se você pretende manter um servidor de e-mail em seu EC2.");
                    } else {
                        buildText(builder, "This IP has been flagged because it's a non email server <a target=\"_blank\" href=\"http://spfbl.net/en/aws/\">generic EC2</a>.");
                        buildText(builder, "Request a <a target=\"_blank\" href=\"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html\">Elastic IP</a> to AWS, with rDNS identification, if you plan to maintain an email server on your EC2.");
                    }
                } else if (reputationStatus != Status.GREEN) {
                    boolean blocked = Block.containsCIDR(ip);
                    if (blocked || reputationStatus == Status.RED) {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            buildText(builder, "Este IP " + (blocked ? "foi bloqueado" : "está listado") + " por má reputação com " + Core.PERCENT_FORMAT.format(reputationProbability) + " de pontos negativos.");
                            buildText(builder, "Para que este IP possa ser removido desta lista, é necessário que o MTA de origem reduza o volume de envios para os destinatários com <a target=\"_blank\" href=\"http://spfbl.net/feedback/\">prefixo de rejeição SPFBL</a> na camada SMTP.");
                            buildText(builder, "O intervalo de reputação é de sete dias, portanto, você deve aguardar esse intervalo após a interrupção de todos os abusos.");
                        } else {
                            buildText(builder, "This IP " + (blocked ? "was blocked" : "is listed") + " by bad reputation in " + Core.PERCENT_FORMAT.format(reputationProbability) + " of negative points.");
                            buildText(builder, "In order for the IP to be removed from this list, the source MTA has to reduce the deliveries to customers who have complained, which have generated a <a target=\"_blank\" href=\"http://spfbl.net/en/feedback/\">SPFBL rejection prefix</a> at the SMTP layer.");
                            buildText(builder, "The reputation interval is seven days, so you should wait for this interval after all abuse has stopped.");
                        }
                    } else {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            buildText(builder, "Este IP não está listado neste sistema porém sua reputação está com " + Core.PERCENT_FORMAT.format(reputationProbability) + " de pontos negativos.");
                            buildText(builder, "Se esta reputação tiver aumento significativo na quantidade de pontos negativos, este IP será automaticamente listado neste sistema.");
                            buildText(builder, "Para evitar que isto ocorra, reduza os envios com <a target=\"_blank\" href=\"http://spfbl.net/feedback/\">prefixo de rejeição SPFBL</a>.");
                        } else {
                            buildText(builder, "This IP is not listed in this system but its reputation is with " + Core.PERCENT_FORMAT.format(reputationProbability) + " of negative points.");
                            buildText(builder, "If this reputation have significant increase in the number of negative points, this IP will automatically be listed in the system.");
                            buildText(builder, "To prevent this from occurring, reduce sending with <a target=\"_blank\" href=\"http://spfbl.net/en/feedback/\">SPFBL rejection prefix</a>.");
                        }
                    }
                } else if (emailMap.isEmpty()) {
                    if (fqdn == null) {
                        boolean blocked = Block.containsCIDR(ip);
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            if (generic) {
                                buildText(builder, "Nenhum <a target=\"_blank\" href=\"http://spfbl.net/generic/\">rDNS genérico</a> será aceito para nomear servidores de e-mail.");
                            } else if (blocked) {
                                buildText(builder, "Este IP foi marcado por não ter <a target=\"_blank\" href=\"http://spfbl.net/fcrdns/\">FCrDNS</a> válido.");
                            } else {
                                buildText(builder, "Este IP não está listado porém não tem um <a target=\"_blank\" href=\"http://spfbl.net/fcrdns/\">FCrDNS</a> válido.");
                            }
                            buildText(builder, "Cadastre um <a target=\"_blank\" href=\"http://spfbl.net/rdns/\">rDNS</a> válido para este IP, que aponte para o mesmo IP.");
                            if (blocked) {
                                buildText(builder, "O <a target=\"_blank\" href=\"http://spfbl.net/rdns/\">rDNS</a> deve estar sob seu próprio domínio para que a liberação seja efetivada.");
                            } else {
                                buildText(builder, "Qualquer IP com <a target=\"_blank\" href=\"http://spfbl.net/fcrdns/\">FCrDNS</a> inválido pode ser listado a qualquer momento.");
                            }
                        } else {
                            if (generic) {
                                buildText(builder, "No <a target=\"_blank\" href=\"http://spfbl.net/en/generic/\">Generic rDNS</a> will be accepted to name email servers.");
                            } else if (blocked) {
                                buildText(builder, "This IP has been flagged because have none valid <a target=\"_blank\" href=\"http://spfbl.net/en/fcrdns/\">FCrDNS</a>.");
                            } else if (FQDN.isBeneficial(fqdn)) {
                                buildText(builder, "This IP has a very good reputation, but does not have a <a target=\"_blank\" href=\"http://spfbl.net/fcrdns/\">FCrDNS</a> válido.");
                            } else {
                                buildText(builder, "This IP isn't listed but have none valid <a target=\"_blank\" href=\"http://spfbl.net/en/fcrdns/\">FCrDNS</a>.");
                            }
                            buildText(builder, "Register a valid <a target=\"_blank\" href=\"http://spfbl.net/en/rdns/\">rDNS</a> for this IP, which points to the same IP.");
                            if (blocked) {
                                buildText(builder, "The <a target=\"_blank\" href=\"http://spfbl.net/en/rdns/\">rDNS</a> must be registered under your own domain for you be able to delist it.");
                            } else {
                                buildText(builder, "Any IP with invalid <a target=\"_blank\" href=\"http://spfbl.net/en/fcrdns/\">FCrDNS</a> can be listed at any time.");
                            }
                        }
                    } else if (Core.hasAdminEmail()) {
                        String adminEmail = Core.getAdminEmail();
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            buildText(builder, "Contacte " + adminEmail + " para solicitar o cadastro de um e-mail abuse para este IP.");
                        } else {
                            buildText(builder, "Contact " + adminEmail + " to request registration of an abuse email for this IP.");
                        }
                    } else {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            buildText(builder, "O IP deste servidor de e-mail não possui um endereço de e-mail de abuso.");
                        } else {
                            buildText(builder, "This mail server IP does not have a abuse mail address.");
                        }
                    }
                } else if (Block.containsCIDR(ip)) {
                    if (parameterMap != null && parameterMap.containsKey("token") && parameterMap.containsKey("PayerID") && Core.hasPayPalAccount()) {
                        try {
                            String paypal_user = Core.getPayPalAccountUser();
                            String paypal_password = Core.getPayPalAccountPassword();
                            String paypal_signature = Core.getPayPalAccountSignature();
                            String paypal_token = (String) parameterMap.get("token");
                            URL url = new URL("https://api-3t.paypal.com/nvp");
                            HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
                            con.setConnectTimeout(3000);
                            con.setReadTimeout(30000);
                            con.setRequestMethod("POST");
                            con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
                            String postParams = "USER=" + paypal_user
                                    + "&PWD=" + paypal_password
                                    + "&SIGNATURE=" + paypal_signature
                                    + "&VERSION=114.0"
                                    + "&METHOD=GetExpressCheckoutDetails"
                                    + "&TOKEN=" + paypal_token
                                    + "";
                            con.setDoOutput(true);
                            try (DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {
                                wr.write(postParams.getBytes("UTF-8"));
                                wr.flush();
                            }
                            StringBuilder response;
                            try (BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
                                String inputLine;
                                response = new StringBuilder();
                                while ((inputLine = in.readLine()) != null) {
                                    response.append(inputLine);
                                }
                            }
                            String decoded = URLDecoder.decode(response.toString(), "UTF-8");
                            Server.logTrace(postParams + " => " + decoded);
                            Properties properties = new Properties();
                            properties.load(new StringReader(decoded.replace("&", "\n")));
                            if (properties.getProperty("ACK").equals("Success")) {
                                String paypal_player_email = properties.getProperty("EMAIL");
                                if (paypal_player_email == null) {
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        buildText(builder, "O PayPal não apresentou o endereço de e-mail da sua conta. Por esse motivo, o processo de remoção não pode ser concluido.");
                                    } else {
                                        buildText(builder, "PayPal did not display the email address of your account. For this reason, the delist process can not be completed.");
                                    }
                                } else if (NoReply.isUnsubscribed(paypal_player_email)) {
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        buildText(builder, "O endereço de e-mail de usuário do PayPal escolhido não pode ser usado para concuir processo de remoção.");
                                    } else {
                                        buildText(builder, "The chosen PayPal user email address cannot be used to complete the delist process.");
                                    }
                                } else if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    buildText(builder, "O PayPal autorizou este pagamento e apresentou o seguinte endereço como e-mail da sua conta:");
                                    builder.append("        <ul>\n");
                                    builder.append("<li>&lt;");
                                    builder.append(paypal_player_email);
                                    builder.append("&gt;</li>");
                                    builder.append("        </ul>\n");
                                    buildText(builder, "Uma vez que você efetivar a remoção deste IP em nossa plataforma, seu e-mail será mostrado publicamente como responsável pelos abusos deste IP.");
                                    buildText(builder, "Clique abaixo se você concorda que mostremos publicamente seu endereço de e-mail como responsável por este IP:");
                                    builder.append("      <form method=\"POST\">\n");
                                    builder.append("        <div id=\"divcaptcha\">\n");
                                    builder.append("          <input id=\"btngo\" type=\"submit\" value=\"Concordo em tornar meu e-mail público\">\n");
                                    builder.append("        </div>\n");
                                    builder.append("      </form>\n");
                                } else {
                                    buildText(builder, "PayPal has authorized this payment and displayed the following address as your account e-mail:");
                                    builder.append("        <ul>\n");
                                    builder.append("<li>&lt;");
                                    builder.append(paypal_player_email);
                                    builder.append("&gt;</li>");
                                    builder.append("        </ul>\n");
                                    buildText(builder, "Once you effectively delist this IP at our platform, your email will be shown publicly as responsible for abuses of this IP.");
                                    buildText(builder, "Click below if you agree that we publicly display your email address as responsible for this IP:");
                                    builder.append("      <form method=\"POST\">\n");
                                    builder.append("        <div id=\"divcaptcha\">\n");
                                    builder.append("          <input id=\"btngo\" type=\"submit\" value=\"I agree to make my email public\">\n");
                                    builder.append("        </div>\n");
                                    builder.append("      </form>\n");
                                }
                            } else {
                                throw new Exception(postParams + " => " + decoded);
                            }
                        } catch (Exception ex) {
                            Server.logError(ex);
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                buildText(builder, "Houve uma falha ao tentar acessar o serviço do PayPal. Tente novamente realizar este procedimento mais tarde.");
                            } else {
                                buildText(builder, "There was a problem trying to access the PayPal service. Please try performing this procedure again later.");
                            }
                        }
                    } else {
                        String abuseEmail = Abuse.getEmail(ip, fqdn);
                        if (fqdn == null) {
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                buildText(builder, "Este IP foi marcado por má configuração do serviço de e-mail ou por suspeita de não haver um MTA nele.");
                            } else {
                                buildText(builder, "This IP was flagged due to misconfiguration of the e-mail service or the suspicion that there is no MTA at it.");
                            }
                        } else if (abuseEmail == null) {
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                buildText(builder, "Este IP foi marcado pela dificuldade em identificar o responsável pelos abusos.");
                            } else {
                                buildText(builder, "This IP was flagged by difficulty in identifying the responsible for abuses.");
                            }
                        } else if (Block.containsFQDN(fqdn)) {
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                buildText(builder, "Este IP foi marcado por suspeita não confirmada de SPAM.");
                            } else {
                                buildText(builder, "This IP was flagged due unconfirmed suspicion of SPAM.");
                            }
                        } else {
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                buildText(builder, "Este IP foi marcado por ser um MTA em desconformidade com a RFC 5321.");
                            } else {
                                buildText(builder, "This IP was flagged to be a MTA not in compliance with RFC 5321.");
                            }
                        }
                        builder.append("      <hr>\n");
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            buildText(builder, "Para que a chave de delist possa ser enviada, selecione o endereço de e-mail do responsável pelo IP:");
                        } else {
                            buildText(builder, "For the delist key can be sent, select the e-mail address responsible for this IP:");
                        }
                        builder.append("      <form method=\"POST\">\n");
                        builder.append("        <ul>\n");
                        int permittedCount = 0;
                        for (String email : emailMap.keySet()) {
                            if (email.startsWith("PAYPAL_")) {
                                permittedCount++;
                            } else if (isValidEmail(email)) {
                                if (emailMap.get(email)) {
                                    if (!Trap.contaisAnything(email)) {
                                        if (!NoReply.contains(email, false)) {
                                            permittedCount++;
                                        }
                                    }
                                }
                            }
                        }
                        boolean permittedChecked = false;
                        Entry<String,Boolean> entry = emailMap.pollFirstEntry();
                        do {
                            String email = entry.getKey();
                            boolean valid = entry.getValue();
                            if (email.startsWith("PAYPAL_")) {
                                String currency = email.substring(7, 10);
                                String price = email.substring(11);
                                builder.append("          <input type=\"radio\" name=\"identifier\" ");
                                builder.append("onclick=\"document.getElementById('btngo').disabled = false;\" value=\"");
                                builder.append(email);
                                builder.append("\"><font style=\"color:#808080\">");
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    builder.append("adicionar um e-mail de usuário do PayPal por ");
                                } else {
                                    builder.append("add a PayPal user's email for ");
                                }
                                builder.append(price);
                                builder.append(" ");
                                builder.append(currency);
                                builder.append(".</font><br>\n");
                            } else if (!isValidEmail(email)) {
                                builder.append("          <input type=\"radio\" name=\"identifier\" value=\"");
                                builder.append(email);
                                builder.append("\" disabled>");
                                builder.append("&lt;");
                                builder.append(email);
                                builder.append("&gt; ");
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    builder.append("inválido.<br>\n");
                                } else {
                                    builder.append("invalid.<br>\n");
                                }
                            } else if (Trap.contaisAnything(email)) {
                                builder.append("          <input type=\"radio\" name=\"identifier\" value=\"");
                                builder.append(email);
                                builder.append("\" disabled>");
                                builder.append("&lt;");
                                builder.append(email);
                                builder.append("&gt; ");
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    builder.append("inexistente.</li><br>\n");
                                } else {
                                    builder.append("non-existent.</li><br>\n");
                                }
                            } else if (NoReply.contains(email, false)) {
                                builder.append("          <input type=\"radio\" name=\"identifier\" value=\"");
                                builder.append(email);
                                builder.append("\" disabled>");
                                builder.append("&lt;");
                                builder.append(email);
                                builder.append("&gt; ");
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    builder.append("desinscrito.<br>\n");
                                } else {
                                    builder.append("unsubscribed.<br>\n");
                                }
                            } else if (valid) {
                                builder.append("          <input type=\"radio\" name=\"identifier\" ");
                                builder.append("onclick=\"document.getElementById('btngo').disabled = false;\" value=\"");
                                builder.append(email);
                                if (permittedChecked) {
                                    builder.append("\">");
                                } else if (permittedCount == 1) {
                                    builder.append("\" checked>");
                                    permittedChecked = true;
                                } else if (abuseEmail == null && email.startsWith("abuse@")) {
                                    builder.append("\" checked>");
                                    permittedChecked = true;
                                } else if (email.equals(abuseEmail)) {
                                    builder.append("\" checked>");
                                    permittedChecked = true;
                                } else {
                                    builder.append("\">");
                                }
                                builder.append("&lt;");
                                builder.append(email);
                                builder.append("&gt; ");
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    builder.append("qualificado.<br>\n");
                                } else {
                                    builder.append("qualified.<br>\n");
                                }
                            } else {
                                builder.append("          <input type=\"radio\" name=\"identifier\" value=\"");
                                builder.append(email);
                                builder.append("\" disabled>");
                                builder.append("&lt;");
                                builder.append(email);
                                builder.append("&gt; ");
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    builder.append("desqualificado.<br>\n");
                                } else {
                                    builder.append("disqualified.<br>\n");
                                }
                            }
                        } while ((entry = emailMap.pollFirstEntry()) != null);
                        builder.append("        </ul>\n");
                        if (permittedCount == 0) {
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                buildText(builder, "Nenhum e-mail de responsável está qualificado para remover o IP nesta plataforma.");
                            } else {
                                buildText(builder, "No responsible email is qualified to remove the IP on this platform.");
                            }
                        } else {
                            if (fqdn == null) {
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    buildText(builder, "O <a target=\"_blank\" href=\"http://spfbl.net/rdns/\">rDNS</a> do IP deve estar sob seu próprio domínio. Não aceitamos <a target=\"_blank\" href=\"http://spfbl.net/rdns/\">rDNS</a> com domínios de terceiros.");
                                } else {
                                    buildText(builder, "The <a target=\"_blank\" href=\"http://spfbl.net/en/rdns/\">rDNS</a> must be registered under your own domain. We do not accept <a target=\"_blank\" href=\"http://spfbl.net/en/rdns/\">rDNS</a> with third-party domains.");
                                }
                            } else {
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    buildText(builder, "Somente o administrador deste servidor de e-mail pode concluir o processo de delist.");
                                } else {
                                    buildText(builder, "Only the administrator of this email server can complete the delist process.");
                                }
                            }
                            builder.append("        <div id=\"divcaptcha\">\n");
                            buildCaptcha(true, builder);
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                builder.append("          <input id=\"btngo\" type=\"submit\" value=\"Solicitar chave de delist\"");
                            } else {
                                builder.append("          <input id=\"btngo\" type=\"submit\" value=\"Request delist key\"");
                            }
                            if (permittedChecked) {
                                builder.append(">\n");
                            } else {
                                builder.append(" disabled>\n");
                            }
                            builder.append("        </div>\n");
                            builder.append("      </form>\n");
                        }
                    }
                } else if (Provider.containsIPorFQDN(ip)) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        buildText(builder, "Este IP pertence a um provedor de envio de e-mail em massa.");
                    } else {
                        buildText(builder, "This IP belongs to a bulk email sending provider.");
                    }
                    String abuseEmail = Abuse.getEmailFqdnOrIP(ip);
                    if (abuseEmail != null) {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            buildText(builder, "E-mail para denúncia de abusos deste IP:");
                        } else {
                            buildText(builder, "Email for abuse complain of this IP:");
                        }
                        builder.append("        <ul>\n");
                        builder.append("            <li>");
                        builder.append(abuseEmail);
                        builder.append("</li>\n");
                        builder.append("        </ul>\n");
                        if (Abuse.isUnsubscribed(abuseEmail)) {
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                buildText(builder, "Este endereço de email abuse está desinscrito da nossa plataforma.");
                            } else {
                                buildText(builder, "This abuse email address was unsubscribed at our platform.");
                            }
                        } else if (Abuse.getFlag(abuseEmail) == BENEFICIAL) {
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                buildText(builder, "Esta equipe de tratamento de abusos é extremamente confiável e por isso esse IP foi colocado em lista branca.");
                            } else {
                                buildText(builder, "This abuse team is extremely reliable and therefore this IP has been whitelisted.");
                            }
                        }
                    }
                } else if (CIDR.isBeneficialFQDN(ip)) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        buildText(builder, "Este IP está com reputação extremamente boa e por isso foi colocado em lista branca.");
                    } else {
                        buildText(builder, "This IP is extremely good reputation and therefore has been whitelisted.");
                    }
                    String abuseEmail = Abuse.getEmailFqdnOrIP(ip);
                    if (abuseEmail != null) {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            buildText(builder, "E-mail para denúncia de abusos deste IP:");
                        } else {
                            buildText(builder, "Email for abuse complain of this IP:");
                        }
                        builder.append("        <ul>\n");
                        builder.append("            <li>");
                        builder.append(abuseEmail);
                        builder.append("</li>\n");
                        builder.append("        </ul>\n");
                        if (Abuse.isUnsubscribed(abuseEmail)) {
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                buildText(builder, "Este endereço de email abuse está desinscrito da nossa plataforma.");
                            } else {
                                buildText(builder, "This abuse email address was unsubscribed at our platform.");
                            }
                        } else if (Abuse.getFlag(abuseEmail) == BENEFICIAL) {
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                buildText(builder, "Esta equipe de tratamento de abusos é extremamente confiável e por isso esse IP foi colocado em lista branca.");
                            } else {
                                buildText(builder, "This abuse team is extremely reliable and therefore this IP has been whitelisted.");
                            }
                        }
                    }
                } else if (Ignore.containsIPorFQDN(ip)) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        buildText(builder, "Este IP está marcado como serviço essencial e por isso foi colocado em lista branca.");
                    } else {
                        buildText(builder, "This IP is marked as an essential service and therefore has been whitelisted.");
                    }
                    String abuseEmail = Abuse.getEmailFqdnOrIP(ip);
                    if (abuseEmail != null) {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            buildText(builder, "E-mail para denúncia de abusos deste IP:");
                        } else {
                            buildText(builder, "Email for abuse complain of this IP:");
                        }
                        builder.append("        <ul>\n");
                        builder.append("            <li>");
                        builder.append(abuseEmail);
                        builder.append("</li>\n");
                        builder.append("        </ul>\n");
                        if (Abuse.isUnsubscribed(abuseEmail)) {
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                buildText(builder, "Este endereço de email abuse está desinscrito da nossa plataforma.");
                            } else {
                                buildText(builder, "This abuse email address was unsubscribed at our platform.");
                            }
                        } else if (Abuse.getFlag(abuseEmail) == BENEFICIAL) {
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                buildText(builder, "Esta equipe de tratamento de abusos é extremamente confiável e por isso esse IP foi colocado em lista branca.");
                            } else {
                                buildText(builder, "This abuse team is extremely reliable and therefore this IP has been whitelisted.");
                            }
                        }
                    }
                } else if (White.containsIPorFQDN(ip)) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        buildText(builder, "Este IP está marcado como serviço de mensagem estritamente corporativo e por isso foi colocado em lista branca.");
                        if (Core.hasAbuseEmail()) {
                            buildText(builder, "Se você tiver recebido alguma mensagem promocional deste IP, sem prévia autorização, faça uma denuncia para " + Core.getAbuseEmail() + ".");
                        }
                    } else {
                        buildText(builder, "This IP is marked as strictly corporate message service and therefore has been whitelisted.");
                        if (Core.hasAbuseEmail()) {
                            buildText(builder, "If you received any promotional message from this IP, without permission, make a complaint to " + Core.getAbuseEmail() + ".");
                        }
                    }
                } else {
                    if (Abuse.isUndesirableRange(ip)) {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            buildText(builder, "Este IP foi listado como equipe de tratamento de abuso não confiável para o mesmo range de IP.");
                        } else {
                            buildText(builder, "This IP was listed as unreliable abuse treatment team for the same IP range.");
                        }
                    } else if (fqdn == null) {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            buildText(builder, "Nenhum registro foi encontrado para este IP.");
                        } else {
                            buildText(builder, "No registry was found for this IP.");
                        }
                    } else {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            buildText(builder, "Este servidor de e-mail está limpo no momento.");
                        } else {
                            buildText(builder, "This email server is currently clean.");
                        }
                    }
                    String abuseEmail = Abuse.getEmailFqdnOrIP(ip);
                    if (abuseEmail != null) {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            buildText(builder, "E-mail para denúncia de abusos deste IP:");
                        } else {
                            buildText(builder, "Email for abuse complain of this IP:");
                        }
                        builder.append("        <ul>\n");
                        builder.append("            <li>");
                        builder.append(abuseEmail);
                        builder.append("</li>\n");
                        builder.append("        </ul>\n");
                        Flag abuseFlag = Abuse.getFlag(abuseEmail);
                        if (abuseFlag == HARMFUL) {
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                buildText(builder, "Esta equipe de tratamento de abusos não é confiável.");
                            } else {
                                buildText(builder, "This abuse team is unreliable.");
                            }
                        } else if (Abuse.isUnsubscribed(abuseEmail)) {
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                buildText(builder, "Este endereço de email abuse está desinscrito da nossa plataforma.");
                            } else {
                                buildText(builder, "This abuse email address was unsubscribed at our platform.");
                            }
                        } else if (abuseFlag == BENEFICIAL) {
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                buildText(builder, "Esta equipe de tratamento de abusos é extremamente confiável e por isso esse IP foi colocado em lista branca.");
                            } else {
                                buildText(builder, "This abuse team is extremely reliable and therefore this IP has been whitelisted.");
                            }
                        }
                    }
                }
            }
        } else if (isSignatureURL(query)) {
            if (urlResult == null) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Estamos verificando o conteúdo da URL. Aguarde...");
                } else {
                    buildText(builder, "We are checking the content of the URL. Wait...");
                }
            } else if (urlResult.equals("BLOCKED")) {
                checkURL.remove(query);
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Esta URL está listada por uso indevido do serviço.");
                } else {
                    buildText(builder, "This URL is blacklisted by misuse of the service.");
                }
            } else if (urlResult.equals("DOUBLE")) {
                checkURL.remove(query);
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Esta URL foi listada por uso duplo de encurtadores.");
                } else {
                    buildText(builder, "This URL was blacklisted for use of double shorteners.");
                }
            } else if (urlResult.equals("HIDDEN")) {
                checkURL.remove(query);
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Esta URL foi listada por ocultar outra maliciosa.");
                } else {
                    buildText(builder, "This URL has been blacklisted for hiding another malicious one.");
                }
            } else if (urlResult.equals("EXECUTABLE")) {
                checkURL.remove(query);
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Esta URL foi listada por ocultar executável malicioso.");
                } else {
                    buildText(builder, "This URL has been blacklisted for hiding malicious executable.");
                }
            } else if (urlResult.equals("THREAT")) {
                checkURL.remove(query);
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Esta URL foi listada por abrigar uma ameaça.");
                } else {
                    buildText(builder, "This URL was blacklisted as having a threat.");
                }
            } else if (urlResult.equals("TIMEOUT")) {
                checkURL.remove(query);
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Esta URL está indisponível no momento.");
                } else {
                    buildText(builder, "This URL is currently unavailable.");
                }
            } else if (urlResult.equals("NXDOMAIN")) {
                checkURL.remove(query);
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Não foi possível acessar esta URL pois este domínio não existe.");
                } else {
                    buildText(builder, "Could not access this URL because its domain does not exist.");
                }
            } else if (urlResult.equals("ERROR")) {
                checkURL.remove(query);
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Houve um erro ao tentar acessar esta URL.");
                } else {
                    buildText(builder, "There was an error while trying to access this URL.");
                }
            } else {
                checkURL.remove(query);
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Nenhuma ameaça foi encontrada para esta URL.");
                } else {
                    buildText(builder, "No threats were found for this URL.");
                }
            }
        } else if (isHostname(query)) {
            String domain = Domain.normalizeHostname(query, true);
            if (domain.equals(".test") || domain.equals(".invalid")) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Este é um domínio reservado e por este motivo não é abordado nesta lista.");
                } else {
                    buildText(builder, "This is a reserved domain and for this reason is not addressed in this list.");
                }
            } else if (Generic.containsDynamic(domain)) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Este hostname tem padrão de <a target=\"_blank\" href=\"http://spfbl.net/dynamic/\">IP dinâmico ou suspeito para uso exclusivamente doméstico.</a>.");
                } else {
                    buildText(builder, "This hostname has pattern of <a target=\"_blank\" href=\"http://spfbl.net/en/dynamic/\">dynamic IP</a> or suspect to be domestic use only.");
                }
            } else if (SPF.getStatus(domain, false) != Status.GREEN) {
                float probability = SPF.getSpamProbability(domain);
                boolean blocked = Block.containsDomain(domain, false);
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Este FQDN " + (blocked ? "foi bloqueado" : "está listado") + " por má reputação com " + Core.PERCENT_FORMAT.format(probability) + " de pontos negativos do volume total de envio.");
                    buildText(builder, "Para que este FQDN possa ser removido desta lista, é necessário que todos os MTAs de origem reduzam o volume de envios para os destinatários com <a target=\"_blank\" href=\"http://spfbl.net/feedback/\">prefixo de rejeição SPFBL</a> na camada SMTP.");
                } else {
                    buildText(builder, "This FQDN " + (blocked ? "was blocked" : "is blacklisted") + " by bad reputation in " + Core.PERCENT_FORMAT.format(probability) + " of negative points of the total shipping volume.");
                    buildText(builder, "In order for this FQDN to be removed from this list, it is necessary for all source MTAs to reduce the volume of submissions to recipients with <a target=\"_blank\" href=\"http://spfbl.net/en/feedback/\">SPFBL rejection prefix</a> in the SMTP layer.");
                }
            } else if (White.containsHostname(domain)) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Este FQDN está marcado como serviço de mensagem estritamente corporativo e por isso foi colocado em lista branca.");
                    if (Core.hasAbuseEmail()) {
                        buildText(builder, "Se você tiver recebido alguma mensagem promocional deste domínio, sem prévia autorização, faça uma denuncia para " + Core.getAbuseEmail() + ".");
                    }
                } else {
                    buildText(builder, "This FQDN is marked as strictly corporate message service and therefore has been whitelisted.");
                    if (Core.hasAbuseEmail()) {
                        buildText(builder, "If you received any promotional message from this domain, without permission, make a complaint to " + Core.getAbuseEmail() + ".");
                    }
                }
            } else if ((domain = Domain.extractDomainSafe(domain, false)) != null && SPF.getStatus(domain) != Status.GREEN) {
                float probability = SPF.getSpamProbability(domain);
                boolean blocked = Block.containsDomain(domain, false);
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "O FQDN " + domain + " " + (blocked ? "foi bloqueado" : "está listado") + " por má reputação com " + Core.PERCENT_FORMAT.format(probability) + " de pontos negativos do volume total de envio.");
                    buildText(builder, "Para que este FQDN possa ser removido desta lista, é necessário que todos os MTAs de origem reduzam o volume de envios para os destinatários com <a target=\"_blank\" href=\"http://spfbl.net/feedback/\">prefixo de rejeição SPFBL</a> na camada SMTP.");
                } else {
                    buildText(builder, "The FQDN " + domain + " " + (blocked ? "was blocked" : "is listed") + " by bad reputation in " + Core.PERCENT_FORMAT.format(probability) + " of negative points of the total shipping volume.");
                    buildText(builder, "In order for this FQDN to be removed from this list, it is necessary for all source MTAs to reduce the volume of submissions to recipients with <a target=\"_blank\" href=\"http://spfbl.net/en/feedback/\">SPFBL rejection prefix</a> in the SMTP layer.");
                }
            } else if (Block.containsDomain(domain, true)) {
                if (Reverse.isInexistentDomain(domain)) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        buildText(builder, "Este FQDN está listado por não existir oficialmente.");
                    } else {
                        buildText(builder, "This FQDN is listed because it does not exist officially.");
                    }
                } else if (Reverse.isUnavailableDomain(domain)) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        buildText(builder, "Este FQDN está listado por estar com serviço DNS indisponível.");
                    } else {
                        buildText(builder, "This FQDN is listed because DNS service is unavailable.");
                    }
                } else {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        buildText(builder, "Este FQDN está listado como suspeita de fonte de SPAM.");
                        TreeSet<String> addressSet = Reverse.getAddressSetSafe(domain);
                        String ip = addressSet.size() == 1 ? addressSet.first() : null;
                        String url = Core.getURL(secured, locale, ip);
                        if (ip != null && url != null && Block.containsCIDR(ip)) {
                            buildText(builder, "Para que este FQDN seja removido desta lista, é necessário desbloquear seu respectivo IP: <a href='" + url + "'>" + ip + "</a>");
                        } else if (Core.hasAdminEmail()) {
                            buildText(builder, "Para que este FQDN seja removido desta lista, é necessário enviar uma solicitação para " + Core.getAdminEmail() + ".");
                        }
                    } else {
                        buildText(builder, "This FQDN is listed as suspected SPAM source.");
                        TreeSet<String> addressSet = Reverse.getAddressSetSafe(domain);
                        String ip = addressSet.size() == 1 ? addressSet.first() : null;
                        String url = Core.getURL(secured, locale, ip);
                        if (ip != null && url != null && Block.containsCIDR(ip)) {
                            buildText(builder, "In order for this FQDN to be removed from this list, it is necessary to unblock its respective IP: <a href='" + url + "'>" + ip + "</a>");
                        } else if (Core.hasAdminEmail()) {
                            buildText(builder, "In order to remove this FQDN from this list, you must send a request to " + Core.getAdminEmail() + ".");
                        }
                    }
                }
            } else if (FQDN.isBeneficial(domain)) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Este FQDN está com reputação extremamente boa e por isso foi colocado em lista branca.");
                } else {
                    buildText(builder, "This FQDN is extremely good reputation and therefore has been whitelisted.");
                }
            } else if (Ignore.containsHost(domain)) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Este FQDN está marcado como serviço essencial e por isso foi colocado em lista branca.");
                } else {
                    buildText(builder, "This FQDN is marked as an essential service and therefore has been whitelisted.");
                }
            } else if (Reverse.isInexistentDomain(domain)) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Este FQDN não está registrado no DNS.");
                } else {
                    buildText(builder, "This FQDN is not registered at DNS.");
                }
            } else {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Nenhum registro foi encontrado para este FQDN.");
                } else {
                    buildText(builder, "No registry was found for this FQDN.");
                }
                TreeSet<String> addressSet = Reverse.getAddressSetSafe(query);
                if (!addressSet.isEmpty()) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        buildText(builder, "Estes são os IPs registrados para esse FQDN:");
                    } else {
                        buildText(builder, "These are the registered IPs for this FQDN:");
                    }
                    builder.append("        <ul>\n");
                    for (String ip : addressSet) {
                        builder.append("          <li>&lt;<a href=\"./");
                        builder.append(ip);
                        builder.append("\">");
                        builder.append(ip);
                        builder.append("</a>&gt; ");
                    }
                    builder.append("        </ul>\n");
                }
                String abuseEmail = Abuse.getEmailFQDN(domain);
                if (abuseEmail != null) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        buildText(builder, "E-mail para denúncia de abusos deste FQDN:");
                    } else {
                        buildText(builder, "Email for abuse complain of this FQDN:");
                    }
                    builder.append("        <ul>\n");
                    builder.append("            <li>");
                    builder.append(abuseEmail);
                    builder.append("</li>\n");
                    builder.append("        </ul>\n");
                }
            }
        }
        buildFooter(builder, locale, null);
        builder.append("    </div>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private static String getRedirectHTML(
            Locale locale,
            String url
    ) {
        StringBuilder builder = new StringBuilder();
        builder.append("<!DOCTYPE html>\n");
        builder.append("<html lang=\"");
        builder.append(locale.getLanguage());
        builder.append("\">\n");
        buildHead(builder, null, url, 0);
        builder.append("</html>\n");
        return builder.toString();
    }

    private static String getControlPanel(
            Locale locale,
            TimeZone timeZone,
            Query query,
            long time
    ) {
        DateFormat dateFormat = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM, locale);
        dateFormat.setTimeZone(timeZone);
        GregorianCalendar calendar = new GregorianCalendar(locale);
        calendar.setTimeZone(timeZone);
        calendar.setTimeInMillis(time);
        StringBuilder builder = new StringBuilder();
        builder.append("<html lang=\"");
        builder.append(locale.getLanguage());
        builder.append("\">\n");
        builder.append("  <head>\n");
        builder.append("    <meta charset=\"UTF-8\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("    <title>Painel de controle do SPFBL</title>\n");
        } else {
            builder.append("    <title>SPFBL control panel</title>\n");
        }
        // Styled page.
        builder.append("    <style type=\"text/css\">\n");
        builder.append("      body {");
        builder.append("        background: #b4b9d2;\n");
        builder.append("      }\n");
        builder.append("      .button {\n");
        builder.append("          background-color: #4CAF50;\n");
        builder.append("          border: none;\n");
        builder.append("          color: white;\n");
        builder.append("          padding: 16px 32px;\n");
        builder.append("          text-align: center;\n");
        builder.append("          text-decoration: none;\n");
        builder.append("          display: inline-block;\n");
        builder.append("          font-size: 16px;\n");
        builder.append("          margin: 4px 2px;\n");
        builder.append("          -webkit-transition-duration: 0.4s;\n");
        builder.append("          transition-duration: 0.4s;\n");
        builder.append("          cursor: pointer;\n");
        builder.append("      }\n");
        builder.append("      .white {\n");
        builder.append("          background-color: white; \n");
        builder.append("          color: black; \n");
        builder.append("          border: 2px solid #4CAF50;\n");
        builder.append("          font-weight: bold;\n");
        builder.append("          cursor: pointer;\n");
        builder.append("      }\n");
        builder.append("      .white:hover {\n");
        builder.append("          background-color: #4CAF50;\n");
        builder.append("          color: white;\n");
        builder.append("      }\n");
        builder.append("      .white:disabled {\n");
        builder.append("          color: white; \n");
        builder.append("          background-color: #4CAF50;\n");
        builder.append("          cursor: not-allowed;\n");
        builder.append("          pointer-events: none;\n");
        builder.append("      }\n");
        builder.append("      .block {\n");
        builder.append("          background-color: white; \n");
        builder.append("          color: black; \n");
        builder.append("          border: 2px solid #f44336;\n");
        builder.append("          font-weight: bold;\n");
        builder.append("          cursor: pointer;\n");
        builder.append("      }\n");
        builder.append("      .block:hover {\n");
        builder.append("          background-color: #f44336;\n");
        builder.append("          color: white;\n");
        builder.append("      }\n");
        builder.append("      .block:disabled {\n");
        builder.append("          color: white; \n");
        builder.append("          background-color: #f44336;\n");
        builder.append("          cursor: not-allowed;\n");
        builder.append("          pointer-events: none;\n");
        builder.append("      }\n");
        builder.append("      .white:disabled::before,\n");
        builder.append("      .block:disabled::before {\n");
        builder.append("          content: \"\\2713\";\n");
        builder.append("          margin-right: 6px;\n");
        builder.append("      }\n");
        builder.append("      .recipient {\n");
        builder.append("          background-color: white; \n");
        builder.append("          color: black; \n");
        builder.append("          border: 2px solid #555555;\n");
        builder.append("          font-weight: bold;\n");
        builder.append("      }\n");
        builder.append("      .recipient:hover {\n");
        builder.append("          background-color: #555555;\n");
        builder.append("          color: white;\n");
        builder.append("      }\n");
        builder.append("    </style>\n");
        builder.append("  </head>\n");
        // Body.
        builder.append("  <body>\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("    <b>Recepção:</b> ");
        } else {
            builder.append("    <b>Reception:</b> ");
        }
        builder.append(dateFormat.format(calendar.getTime()));
        builder.append("<br>\n");
        String sender = query.getSenderSimplified(false, false);
        if (sender == null) {
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("    <b>Remetente:</b> MAILER-DAEMON");
            } else {
                builder.append("    <b>Sender:</b> MAILER-DAEMON");
            }
        } else if (query.getQualifierName().equals("PASS")) {
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("    <b>Remetente autêntico:</b> ");
            } else {
                builder.append("    <b>Genuine sender:</b> ");
            }
            builder.append(sender);
        } else if (query.getQualifierName().equals("FAIL")) {
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("    <b>Remetente falso:</b> ");
            } else {
                builder.append("    <b>False sender:</b> ");
            }
            builder.append(sender);
        } else {
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("    <b>Remetente suspeito:</b> ");
            } else {
                builder.append("    <b>Suspect sender:</b> ");
            }
            builder.append(sender);
        }
        builder.append("<br>\n");
        String filter = query.getFilter();
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("    <b>Filtro:</b> ");
        } else {
            builder.append("    <b>Filter:</b> ");
        }
        if (filter == null) {
            builder.append("NONE");
        } else {
            builder.append(filter);
        }
        builder.append("<br>\n");
        URL unsubscribe = query.getUnsubscribeURL();
        if (unsubscribe == null) {
            builder.append("    <br>\n");
        } else {
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("     <b>Cancelar inscrição:</b> ");
            } else {
                builder.append("     <b>List unsubscribe:</b> ");
            }
            builder.append("<a target=\"_blank\" href=\"");
            builder.append(unsubscribe);
            builder.append("\">");
            builder.append(unsubscribe.getHost());
            builder.append(unsubscribe.getPath());
            builder.append("</a><br>\n");
        }
        if (query.isFilter(ABUSE_SUBMISSION)) {
            String abuse = query.getAbuseReported();
            if (abuse == null) {
                abuse = query.getAbuseSender();
                if (abuse == null) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("     Endereço de e-mail de FBL não cadastrado.");
                    } else {
                        builder.append("     FBL email address not registered.");
                    }
                } else if (NoReply.isUnsubscribed(abuse)) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("     O relatório de abuso não será encaminhado pois o endereço ");
                        builder.append(abuse);
                        builder.append(" está desinscrito.");
                    } else {
                        builder.append("     The abuse report will not be forwarded as address ");
                        builder.append(abuse);
                        builder.append(" is unsubscribed. ");
                    }
                } else {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("     O relatório de abuso será encaminhado para ");
                    } else {
                        builder.append("     The abuse report will be forwarded to ");
                    }
                    builder.append(abuse);
                }
            } else {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("     O relatório de abuso foi encaminhado para ");
                } else {
                    builder.append("     The abuse report was forwarded to ");
                }
                builder.append(abuse);
                builder.append('.');
            }
        } else {
            String recipient = query.getRecipient();
            Long trapTime = query.getTrapTime();
            builder.append("    <form method=\"POST\">\n");

            boolean whited = query.isWhiteKey();
            boolean blocked = query.isBlockKey();

            builder.append("      <button type=\"submit\" class=\"white\" name=\"POLICY\" value=\"WHITE_KEY\"");
            if (whited) {
                builder.append(" disabled>");
            } else {
                builder.append(">");
            }
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("Desejável");
            } else {
                builder.append("Wanted");
            }
            builder.append("</button>\n");
            builder.append("      <button type=\"submit\" class=\"block\" name=\"POLICY\" value=\"BLOCK_KEY\"");
            if (!whited && blocked) {
                builder.append(" disabled>");
            } else {
                builder.append(">");
            }
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("Indesejável");
            } else {
                builder.append("Unwanted");
            }
            builder.append("</button>\n");

            if (!blocked && recipient != null && trapTime != null && query.getUser().isPostmaster()) {
                builder.append("      <button type=\"submit\" class=\"recipient\" name=\"POLICY\" value=\"WHITE_RECIPIENT\">");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("Tornar ");
                    builder.append(recipient);
                    builder.append(" existente");
                } else {
                    builder.append("Make ");
                    builder.append(recipient);
                    builder.append(" existent");
                }
                builder.append("</button>\n");
            } else if (query.hasMalware()) {
                if (query.ignoreMalware()) {
                    builder.append("      <button type=\"submit\" class=\"recipient\" name=\"POLICY\" value=\"BLOCK_MALWARE\">");
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("Reconsiderar ");
                        builder.append(query.getMalware());
                    } else {
                        builder.append("Reconsider ");
                        builder.append(query.getMalware());
                    }
                    builder.append("</button>\n");
                } else {
                    builder.append("      <button type=\"submit\" class=\"recipient\" name=\"POLICY\" value=\"WHITE_MALWARE\">");
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("Ignorar ");
                        builder.append(query.getMalware());
                    } else {
                        builder.append("Ignore ");
                        builder.append(query.getMalware());
                    }
                    builder.append("</button>\n");
                }
            } else if (NoReply.isUnsubscribed(recipient)) {
                builder.append("      <button type=\"submit\" class=\"recipient\" name=\"POLICY\" value=\"WHITE_RECIPIENT\">");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("Reinscrever ");
                    builder.append(recipient);
                } else {
                    builder.append("Resubscribe ");
                    builder.append(recipient);
                }
                builder.append("</button>\n");
            }
            builder.append("    </form>\n");
        }
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private static void buildQueryRow(
            Locale locale,
            TimeZone timeZone,
            StringBuilder builder,
            DateFormat dateFormat,
            GregorianCalendar calendar,
            long timeKey,
            User.Query query,
            boolean highlight
    ) {
        if (query != null) {
            calendar.setTimeInMillis(timeKey);
            String client = query.getClient();
            String queueID = query.getQueueID();
            String ip = query.getIP();
            String hostname = query.getFQDN();
            String sender = query.getTrueSender();
            String from = query.getFrom();
            String replyto = query.getReplyTo();
            String subject = query.getSubject();
            Timestamp date = query.getMessageDate();
            String malware = query.getMalware();
            String recipient = query.getRecipient();
            String result = query.getResult();
            builder.append("        <tr id=\"");
            builder.append(timeKey);
            builder.append("\"");
            if (highlight) {
                builder.append(" class=\"highlight\"");
            } else {
                builder.append(" class=\"click\"");
            }
            builder.append(" onclick=\"view('");
            builder.append(timeKey);
            builder.append("')\">\n");
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("          <td style=\"width:120px;\">");
            } else {
                builder.append("          <td style=\"width:160px;\">");
            }
            builder.append(dateFormat.format(calendar.getTime()));
            builder.append("<br>");
            builder.append(client);
            if (queueID != null && queueID.length() > 0) {
                builder.append("<br><small>");
                builder.append(queueID);
                builder.append("</small>");
            }
            builder.append("</td>\n");
            builder.append("          <td>");
            if (hostname == null) {
                String helo = query.getHELO();
                if (helo == null) {
                    builder.append(ip);
                } else if (isValidIP(helo)) {
                    builder.append(ip);
                } else {
                    builder.append(ip);
                    builder.append("<br>");
                    builder.append("<strike>");
                    builder.append(helo);
                    builder.append("</strike>");
                }
            } else if (Provider.containsDomain(hostname)) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("<small><i>Provedor</i></small>");
                } else {
                    builder.append("<small><i>Provider</i></small>");
                }
                builder.append("<br>");
                builder.append(hostname);
            } else if (Generic.containsGenericSoft(hostname)) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("<small><i>Genérico</i></small>");
                } else {
                    builder.append("<small><i>Generic</i></small>");
                }
                builder.append("<br>");
                builder.append(hostname);
            } else {
                builder.append(hostname);
            }
            String abuse = query.getAbuseReported();
            if (abuse != null) {
                builder.append("<br>");
                builder.append(abuse);
            }
            builder.append("</td>\n");
            TreeSet<String> senderSet = new TreeSet<>();
            builder.append("          <td>");
            if (sender == null) {
                builder.append("MAILER-DAEMON");
            } else {
                senderSet.add(sender);
                Qualifier qualifier = query.getQualifier();
                if (qualifier == PASS) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("<small><i>Autêntico</i></small>");
                    } else {
                        builder.append("<small><i>Genuine</i></small>");
                    }
                } else if (qualifier == FAIL) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("<small><i>Falso</i></small>");
                    } else {
                        builder.append("<small><i>False</i></small>");
                    }
                } else if (qualifier == SOFTFAIL) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("<small><i>Pode ser falso</i></small>");
                    } else {
                        builder.append("<small><i>May be false</i></small>");
                    }
                } else if (qualifier == null) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("<small><i>Sem validação</i></small>");
                    } else {
                        builder.append("<small><i>No validation</i></small>");
                    }
                } else {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("<small><i>Pode ser autêntico</i></small>");
                    } else {
                        builder.append("<small><i>May be genuine</i></small>");
                    }
                }
                builder.append("<br>");
                builder.append(sender);
            }
            boolean lineSeparator = false;
            if (from != null && !senderSet.contains(from)) {
                senderSet.add(from);
                builder.append("<hr style=\"height:0px;visibility:hidden;margin-bottom:0px;\">");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("<small><b>De:</b> ");
                } else {
                    builder.append("<small><b>From:</b> ");
                }
                builder.append(from);
                builder.append("</small>");
                lineSeparator = true;
            }
            if (replyto != null && !senderSet.contains(replyto)) {
                senderSet.add(replyto);
                if (lineSeparator) {
                    builder.append("<br>");
                } else {
                    builder.append("<hr style=\"height:0px;visibility:hidden;margin-bottom:0px;\">");
                }
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("<small><b>Responder para:</b> ");
                } else {
                    builder.append("<small><b>Reply to:</b> ");
                }
                builder.append(replyto);
                builder.append("</small>");
            }
            builder.append("</td>\n");
            builder.append("          <td>");
            if (subject != null) {
                if (date != null) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("<small><b>Data:</b> ");
                    } else {
                        builder.append("<small><b>Date:</b> ");
                    }
                    builder.append(dateFormat.format(date));
                    builder.append("</small><br>");
                }
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("<small><b>Assunto:</b> ");
                } else {
                    builder.append("<small><b>Subject:</b> ");
                }
                builder.append(subject);
                builder.append("</small>");
                builder.append("<hr style=\"height:0px;visibility:hidden;margin-bottom:0px;\">");
            }
            String textBody = query.getTextPlainBody(128);
            if (textBody != null) {
                builder.append("<small>");
                builder.append(StringEscapeUtils.escapeHtml4(textBody));
                builder.append("</small><br><br>");
            }
            TreeSet<String> linkSet = query.getLinkSet();
            if (malware == null) {
                if (linkSet == null) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("<small><i>Corpo não verificado</i></small>");
                    } else {
                        builder.append("<small><i>Body not verified</i></small>");
                    }
                } else if (linkSet.isEmpty()) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("<small><i>Sem links</i></small>");
                    } else {
                        builder.append("<small><i>No links</i></small>");
                    }
                } else {
                    String link = linkSet.pollFirst();
                    if (query.isLinkBlocked(link)) {
                        builder.append("<font color=\"DarkRed\"><b>");
                        builder.append(Core.tryGetSignatureRootURL(link));
                        builder.append("</b></font>");
                    } else {
                        builder.append(Core.tryGetSignatureRootURL(link));
                    }
                    while (!linkSet.isEmpty()) {
                        builder.append("<br>");
                        link = linkSet.pollFirst();
                        if (query.isLinkBlocked(link)) {
                            builder.append("<font color=\"DarkRed\"><b>");
                            builder.append(Core.tryGetSignatureRootURL(link));
                            builder.append("</b></font>");
                        } else {
                            builder.append(Core.tryGetSignatureRootURL(link));
                        }
                    }
                }
            } else if (query.wasAccepted()) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("<small><i>Malware ignorado</i></small>");
                } else {
                    builder.append("<small><i>Malware ignored</i></small>");
                }
                if (!malware.equals("FOUND")) {
                    builder.append("<br>");
                    builder.append("<strike>");
                    builder.append(malware);
                    builder.append("</strike>");
                }
            } else {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("<small><i>Malware encontrado</i></small>");
                } else {
                    builder.append("<small><i>Malware found</i></small>");
                }
                if (!malware.equals("FOUND")) {
                    builder.append("<br>");
                    builder.append("<font color=\"DarkRed\"><b>");
                    builder.append(malware);
                    builder.append("</b></font>");
                }
            }
            builder.append("</td>\n");
            builder.append("          <td>");
            if (result.equals("REJECT")) {
                if (query.hasMalware()) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("Rejeitada por segurança");
                    } else {
                        builder.append("Rejected by security");
                    }
                } else if (query.isAnyLinkBLOCK(timeKey, false)) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("Rejeitada por conteúdo indesejado");
                    } else {
                        builder.append("Rejected by unwanted content");
                    }
                } else if (query.hasExecutableNotIgnored()) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("Rejeitado por executável suspeito");
                    } else {
                        builder.append("Rejected by suspicious executable");
                    }
                } else if (query.isFail() && query.isFromNotSigned()) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("Rejeitado por remetente suspeito");
                    } else {
                        builder.append("Rejected by suspicious sender");
                    }
                } else if (query.isSpoofingFrom()) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("Rejeitado por remetente suspeito");
                    } else {
                        builder.append("Rejected by suspicious sender");
                    }
                } else if (query.isFromBlocked()) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("Rejeitado por remetente suspeito");
                    } else {
                        builder.append("Rejected by suspicious sender");
                    }
                } else if (!query.hasSubject()) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("Rejeitada por origem suspeita");
                    } else {
                        builder.append("Rejected by suspect origin");
                    }
                } else if (!query.hasMailFrom() && !query.hasHeaderFrom()) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("Rejeitada por ausência do remetente");
                    } else {
                        builder.append("Rejected by absence of sender");
                    }
                } else {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("Rejeitada por origem suspeita");
                    } else {
                        builder.append("Rejected by suspected origin");
                    }
                }
                if (recipient != null) {
                    builder.append("<br>");
                    builder.append(recipient);
                }
            } else if (result.equals("BLOCK") || result.equals("BLOCKED")) {
                if (query.hasMalwareNotIgnored()) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("Rejeitada por segurança");
                    } else {
                        builder.append("Rejected by security");
                    }
                } else {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("Rejeitada por bloqueio");
                    } else {
                        builder.append("Rejected by blocking");
                    }
                }
                if (recipient != null) {
                    builder.append("<br>");
                    builder.append(recipient);
                }
            } else if (result.equals("FAIL") || result.equals("FAILED")) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("Rejeitada por falsidade");
                } else {
                    builder.append("Rejected by falseness");
                }
            } else if (result.equals("INVALID")) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("Rejeitada por origem inválida");
                } else {
                    builder.append("Rejected by invalid source");
                }
            } else if (result.equals("GREYLIST")) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("Atrasada por greylisting");
                } else {
                    builder.append("Delayed by greylisting");
                }
                if (recipient != null) {
                    builder.append("<br>");
                    builder.append(recipient);
                }
            } else if (result.equals("SPAMTRAP") || result.equals("TRAP")) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("Descartada pela armadilha");
                } else {
                    builder.append("Discarded by spamtrap");
                }
                if (recipient != null) {
                    builder.append("<br>");
                    builder.append(recipient);
                }
            } else if (result.equals("INEXISTENT")) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("Rejeitada por inexistência");
                } else {
                    builder.append("Rejected by non-existence");
                }
                if (recipient != null) {
                    builder.append("<br>");
                    builder.append(recipient);
                }
            } else if (result.equals("WHITE")) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("Aceita prioritariamente");
                } else {
                    builder.append("Accepted as a priority");
                }
                if (recipient != null) {
                    builder.append("<br>");
                    builder.append(recipient);
                }
            } else if (result.equals("ACCEPT")) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("Aceita");
                } else {
                    builder.append("Accepted");
                }
                if (recipient != null) {
                    builder.append("<br>");
                    builder.append(recipient);
                }
            } else if (result.equals("FLAG")) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("Marcada como suspeita");
                } else {
                    builder.append("Marked as suspect");
                }
                if (recipient != null) {
                    builder.append("<br>");
                    builder.append(recipient);
                }
            } else if (result.equals("HOLD")) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("Mensagem retida");
                } else {
                    builder.append("Retained message");
                }
                if (recipient != null) {
                    builder.append("<br>");
                    builder.append(recipient);
                }
            } else if (result.equals("NXDOMAIN")) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("Rejeitada por domínio inexistente");
                } else {
                    builder.append("Rejected by non-existent domain");
                }
            } else if (result.equals("NXSENDER")) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("Rejeitada por remetente inexistente");
                } else {
                    builder.append("Rejected by non-existent sender");
                }
            } else if (result.equals("QUEUE")) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("Enfileirada");
                } else {
                    builder.append("Queued");
                }
            } else {
                builder.append(result);
                if (recipient != null) {
                    builder.append("<br>");
                    builder.append(recipient);
                }
            }
            builder.append("</td>\n");
            builder.append("        </tr>\n");
        }
    }

    private static String getControlPanel(
            Locale locale,
            TimeZone timeZone,
            User user,
            Long begin,
            String filter
    ) {
        StringBuilder builder = new StringBuilder();
        if (begin == null && filter == null) {
            builder.append("<html lang=\"");
            builder.append(locale.getLanguage());
            builder.append("\">\n");
            builder.append("  <head>\n");
            builder.append("    <meta charset=\"UTF-8\">\n");
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("    <title>Painel de controle do SPFBL</title>\n");
            } else {
                builder.append("    <title>SPFBL control panel</title>\n");
            }
            // Styled page.
            builder.append("    <style type=\"text/css\">\n");
            builder.append("      body {\n");
            builder.append("        margin:180px 0px 30px 0px;\n");
            builder.append("        background:lightgray;\n");
            builder.append("      }\n");
            builder.append("      iframe {\n");
            builder.append("        border-width: 0px 0px 0px 0px;\n");
            builder.append("        width:100%;\n");
            builder.append("        height:150px;\n");
            builder.append("      }\n");
            builder.append("      .header {\n");
            builder.append("        background-color:lightgray;\n");
            builder.append("        border-width: 0px 0px 0px 0px;\n");
            builder.append("        position:fixed;\n");
            builder.append("        top:0px;\n");
            builder.append("        margin:auto;\n");
            builder.append("        z-index:1;\n");
            builder.append("        width:100%;\n");
            builder.append("        height:180px;\n");
            builder.append("      }\n");
            builder.append("      .bottom {\n");
            builder.append("        background-color:lightgray;\n");
            builder.append("        border-width: 0px 0px 0px 0px;\n");
            builder.append("        position:fixed;\n");
            builder.append("        bottom:0px;\n");
            builder.append("        margin:auto;\n");
            builder.append("        z-index:1;\n");
            builder.append("        width:100%;\n");
            builder.append("        height:30px;\n");
            builder.append("      }\n");
            builder.append("      .button {\n");
            builder.append("          background-color: #4CAF50;\n");
            builder.append("          border: none;\n");
            builder.append("          color: white;\n");
            builder.append("          padding: 16px 32px;\n");
            builder.append("          text-align: center;\n");
            builder.append("          text-decoration: none;\n");
            builder.append("          display: inline-block;\n");
            builder.append("          font-size: 16px;\n");
            builder.append("          margin: 4px 2px;\n");
            builder.append("          -webkit-transition-duration: 0.4s;\n");
            builder.append("          transition-duration: 0.4s;\n");
            builder.append("          cursor: pointer;\n");
            builder.append("      }\n");
            builder.append("      .sender {\n");
            builder.append("          background-color: white; \n");
            builder.append("          color: black; \n");
            builder.append("          border: 2px solid #008CBA;\n");
            builder.append("          width: 100%;\n");
            builder.append("          word-wrap: break-word;\n");
            builder.append("      }\n");
            builder.append("      .sender:hover {\n");
            builder.append("          background-color: #008CBA;\n");
            builder.append("          color: white;\n");
            builder.append("      }\n");
            builder.append("      .highlight {\n");
            builder.append("        background: #b4b9d2;\n");
            builder.append("        color:black;\n");
            builder.append("        border-top: 1px solid #22262e;\n");
            builder.append("        border-bottom: 1px solid #22262e;\n");
            builder.append("      }\n");
            builder.append("      .highlight:nth-child(odd) td {\n");
            builder.append("        background: #b4b9d2;\n");
            builder.append("      }\n");
            builder.append("      .click {\n");
            builder.append("        cursor:pointer;\n");
            builder.append("        cursor:hand;\n");
            builder.append("      }\n");
            builder.append("      table {\n");
            builder.append("        background: white;\n");
            builder.append("        table-layout:fixed;\n");
            builder.append("        border-collapse: collapse;\n");
            builder.append("        word-wrap:break-word;\n");
            builder.append("        border-radius:3px;\n");
            builder.append("        border-collapse: collapse;\n");
            builder.append("        margin: auto;\n");
            builder.append("        padding:2px;\n");
            builder.append("        width: 100%;\n");
            builder.append("        box-shadow: 0 5px 10px rgba(0, 0, 0, 0.1);\n");
            builder.append("        animation: float 5s infinite;\n");
            builder.append("      }\n");
            builder.append("      th {\n");
            builder.append("        color:#FFFFFF;;\n");
            builder.append("        background:#1b1e24;\n");
            builder.append("        border-bottom:4px solid #9ea7af;\n");
            builder.append("        border-right: 0px;\n");
            builder.append("        font-size:16px;\n");
            builder.append("        font-weight: bold;\n");
            builder.append("        padding:4px;\n");
            builder.append("        text-align:left;\n");
            builder.append("        text-shadow: 0 1px 1px rgba(0, 0, 0, 0.1);\n");
            builder.append("        vertical-align:middle;\n");
            builder.append("        height:30px;\n");
            builder.append("      }\n");
            builder.append("      tr {\n");
            builder.append("        border-top: 1px solid #C1C3D1;\n");
            builder.append("        border-bottom-: 1px solid #C1C3D1;\n");
            builder.append("        font-size:16px;\n");
            builder.append("        font-weight:normal;\n");
            builder.append("        text-shadow: 0 1px 1px rgba(256, 256, 256, 0.1);\n");
            builder.append("      }\n");
            builder.append("      tr:nth-child(odd) td {\n");
            builder.append("        background:#EBEBEB;\n");
            builder.append("      }\n");
            builder.append("      td {\n");
            builder.append("        padding:2px;\n");
            builder.append("        vertical-align:middle;\n");
            builder.append("        font-size:16px;\n");
            builder.append("        text-shadow: -1px -1px 1px rgba(0, 0, 0, 0.1);\n");
            builder.append("        border-right: 1px solid #C1C3D1;\n");
            builder.append("      }\n");
            builder.append("      input[type=text], select {\n");
            builder.append("        width: 400px;\n");
            builder.append("        padding: 0px 4px;\n");
            builder.append("        margin: 1px 0;\n");
            builder.append("        display: inline-block;\n");
            builder.append("        background: #b4b9d2;\n");
            builder.append("        border: 1px solid #ccc;\n");
            builder.append("        border-radius: 4px;\n");
            builder.append("        box-sizing: border-box;\n");
            builder.append("      }\n");
            builder.append("    </style>\n");
            // JavaScript functions.
            TreeMap<Long,Query> queryMap = user.getQueryMap(null, null);
            builder.append("    <script type=\"text/javascript\" src=\"https://ajax.googleapis.com/ajax/libs/jquery/2.1.3/jquery.min.js\"></script>\n");
            builder.append("    <script type=\"text/javascript\">\n");
            builder.append("      window.onbeforeunload = function () {\n");
            builder.append("        document.getElementById('filterField').value = '';\n");
            builder.append("        window.scrollTo(0, 0);\n");
            builder.append("      }\n");
            builder.append("      var last = ");
            if (queryMap == null) {
                builder.append(0);
            } else if (queryMap.isEmpty()) {
                builder.append(0);
            } else {
                builder.append(queryMap.lastKey());
            }
            builder.append(";\n");
            builder.append("      var filterText = '';\n");
            builder.append("      function view(query) {\n");
            builder.append("        if (query == undefined || query == 'rowMore' || query == 0) {\n");
            builder.append("          var viewer = document.getElementById('viewer');\n");
            builder.append("          viewer.src = 'about:blank';\n");
            builder.append("          last = 0;\n");
            builder.append("        } else if (last != query) {\n");
            builder.append("          var viewer = document.getElementById('viewer');\n");
            builder.append("          viewer.src = 'about:blank';\n");
            builder.append("          viewer.addEventListener('load', function() {\n");
            builder.append("            if (document.getElementById(last)) {\n");
            builder.append("              document.getElementById(last).className = 'tr';\n");
            builder.append("              document.getElementById(last).className = 'click';\n");
            builder.append("            }\n");
            builder.append("            document.getElementById(query).className = 'highlight';\n");
            builder.append("            last = query;\n");
            builder.append("          });\n");
            builder.append("          viewer.src = '/' + query;\n");
            builder.append("        }\n");
            builder.append("      }\n");
            builder.append("      function more(query) {\n");
            builder.append("        filterField = document.getElementById('filterField');\n");
            builder.append("        filterField.disabled = true;\n");
            builder.append("        var rowMore = document.getElementById('rowMore');\n");
            builder.append("        rowMore.onclick = '';\n");
            builder.append("        rowMore.className = 'tr';\n");
            builder.append("        var columnMore = document.getElementById('columnMore');\n");
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("        columnMore.innerHTML = 'carregando mais registros';\n");
            } else {
                builder.append("        columnMore.innerHTML = 'loading more records';\n");
            }
            builder.append("        $.post(\n");
            builder.append("          '/");
            builder.append(user.getEmail());
            builder.append("',\n");
            builder.append("          {filter:filterText,begin:query},\n");
            builder.append("          function(data, status) {\n");
            builder.append("            if (status == 'success') {\n");
            builder.append("              rowMore.parentNode.removeChild(rowMore);\n");
            builder.append("              $('#tableBody').append(data);\n");
            builder.append("            } else {\n");
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("              alert('Houve uma falha de sistema ao tentar realizar esta operação.');\n");
            } else {
                builder.append("              alert('There was a system crash while trying to perform this operation.');\n");
            }
            builder.append("            }\n");
            builder.append("            filterField.disabled = false;\n");
            builder.append("          }\n");
            builder.append("        );\n");
            builder.append("      }\n");
            builder.append("      function refresh() {\n");
            builder.append("        var viewer = document.getElementById('viewer');\n");
            builder.append("        viewer.src = 'about:blank';\n");
            builder.append("        filterField = document.getElementById('filterField');\n");
            builder.append("        filterField.disabled = true;\n");
            builder.append("        filterText = filterField.value;\n");
            builder.append("        $.post(\n");
            builder.append("          '/");
            builder.append(user.getEmail());
            builder.append("',\n");
            builder.append("          {filter:filterText},\n");
            builder.append("          function(data, status) {\n");
            builder.append("            if (status == 'success') {\n");
            builder.append("              $('#tableBody').html(data);\n");
            builder.append("              view($('#tableBody tr').attr('id'));\n");
            builder.append("            } else {\n");
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("              alert('Houve uma falha de sistema ao tentar realizar esta operação.');\n");
            } else {
                builder.append("              alert('There was a system crash while trying to perform this operation.');\n");
            }
            builder.append("            }\n");
            builder.append("            filterField.disabled = false;\n");
            builder.append("          }\n");
            builder.append("        );\n");
            builder.append("      }\n");
            builder.append("    </script>\n");
            builder.append("  </head>\n");
            // Body.
            builder.append("  <body>\n");
            builder.append("    <div class=\"header\">\n");
            if (queryMap == null) {
                builder.append("      <iframe id=\"viewer\" src=\"about:blank\"></iframe>\n");
            } else if (queryMap.isEmpty()) {
                builder.append("      <iframe id=\"viewer\" src=\"about:blank\"></iframe>\n");
            } else {
                builder.append("      <iframe id=\"viewer\" src=\"/");
                builder.append(queryMap.lastKey());
                builder.append("\"></iframe>\n");
            }
            // Construção da tabela de consultas.
            builder.append("      <table>\n");
            builder.append("        <thead>\n");
            builder.append("          <tr>\n");
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("            <th style=\"width:120px;\">Recepção</th>\n");
                builder.append("            <th>Origem</th>\n");
                builder.append("            <th>Remetente</th>\n");
                builder.append("            <th>Conteúdo</th>\n");
                builder.append("            <th>Entrega</th>\n");
            } else {
                builder.append("            <th style=\"width:160px;\">Reception</th>\n");
                builder.append("            <th style=\"width:auto;\">Source</th>\n");
                builder.append("            <th style=\"width:auto;\">Sender</th>\n");
                builder.append("            <th style=\"width:auto;\">Content</th>\n");
                builder.append("            <th style=\"width:auto;\">Delivery</th>\n");
            }
            builder.append("          </tr>\n");
            builder.append("        </thead>\n");
            builder.append("      </table>\n");
            builder.append("    </div>\n");
            if (queryMap == null) {
                builder.append("    <table>\n");
                builder.append("      <tbody>\n");
                builder.append("        <tr>\n");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("          <td colspan=\"5\" align=\"center\">serviço indisponível</td>\n");
                } else {
                    builder.append("          <td colspan=\"5\" align=\"center\">service unavailable</td>\n");
                }
                builder.append("        </tr>\n");
                builder.append("      </tbody>\n");
                builder.append("    </table>\n");
            } else if (queryMap.isEmpty()) {
                builder.append("    <table>\n");
                builder.append("      <tbody>\n");
                builder.append("        <tr>\n");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("          <td colspan=\"5\" align=\"center\">nenhum registro encontrado</td>\n");
                } else {
                    builder.append("          <td colspan=\"5\" align=\"center\">no records found</td>\n");
                }
                builder.append("        </tr>\n");
                builder.append("      </tbody>\n");
                builder.append("    </table>\n");
            } else {
                DateFormat dateFormat = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM, locale);
                dateFormat.setTimeZone(timeZone);
                GregorianCalendar calendar = new GregorianCalendar(locale);
                calendar.setTimeZone(timeZone);
                builder.append("    <table>\n");
                builder.append("      <tbody id=\"tableBody\">\n");
                boolean noMore = true;
                for (long timeKey : queryMap.descendingKeySet()) {
                    User.Query query = queryMap.get(timeKey);
                    if (query == null) {
                        calendar.setTimeInMillis(timeKey);
                        noMore = false;
                        builder.append("        <tr id=\"rowMore\" class=\"click\" onclick=\"more('");
                        builder.append(timeKey);
                        builder.append("')\">\n");
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            builder.append("          <td id=\"columnMore\" colspan=\"5\" align=\"center\">clique para ver mais registros antes de ");
                        } else {
                            builder.append("          <td id=\"columnMore\" colspan=\"5\" align=\"center\">click to see more records before ");
                        }
                        String date = dateFormat.format(calendar.getTime());
                        int index = date.indexOf(' ');
                        date = date.substring(0, index);
                        builder.append(date);
                        builder.append("</td>\n");
                        builder.append("        </tr>\n");
                    } else {
                        boolean highlight = queryMap.lastKey().equals(timeKey);
                        buildQueryRow(locale, timeZone, builder, dateFormat, calendar, timeKey, query, highlight);
                    }
                }
                if (noMore) {
                    builder.append("      <tr>\n");
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("        <td colspan=\"5\" align=\"center\">não foram encontrados outros registros</td>\n");
                    } else {
                        builder.append("        <td colspan=\"5\" align=\"center\">no more records found</td>\n");
                    }
                    builder.append("      </tr>\n");
                }
                builder.append("      </tbody>\n");
                builder.append("    </table>\n");
            }
            builder.append("    <div class=\"bottom\">\n");
            builder.append("      <table>\n");
            builder.append("        <tr>\n");
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("          <th>Pesquisar <input type=\"text\" id=\"filterField\" name=\"filterField\" onkeydown=\"if (event.keyCode == 13) refresh();\" autofocus></th>\n");
            } else {
                builder.append("          <th>Search <input type=\"text\" id=\"filterField\" name=\"filterField\" onkeydown=\"if (event.keyCode == 13) refresh();\" autofocus></th>\n");
            }
            builder.append("          <th style=\"text-align:right;\"><small>");
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("Powered by <a target=\"_blank\" href=\"http://spfbl.net/\" style=\"color: #b4b9d2;\">SPFBL.net</a></small>");
            } else {
                builder.append("Powered by <a target=\"_blank\" href=\"http://spfbl.net/en/\" style=\"color: #b4b9d2;\">SPFBL.net</a></small>");
            }
            builder.append("</th>\n");
            builder.append("        </tr>\n");
            builder.append("      <table>\n");
            builder.append("    </div>\n");
            builder.append("  </body>\n");
            builder.append("</html>\n");
        } else {
            TreeMap<Long,Query> queryMap = user.getQueryMap(begin, filter);
            if (queryMap == null) {
                builder.append("        <tr id=\"rowMore\" class=\"click\" onclick=\"more('");
                builder.append(begin);
                builder.append("')\">\n");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("          <td id=\"columnMore\" colspan=\"5\" align=\"center\">tempo esgotado. tente novamente</td>\n");
                } else {
                    builder.append("          <td id=\"columnMore\" colspan=\"5\" align=\"center\">timeout. try again</td>\n");
                }
                builder.append("        </tr>\n");
            } else if (queryMap.isEmpty()) {
                builder.append("        <tr>\n");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("          <td colspan=\"5\" align=\"center\">nenhum registro encontrado</td>\n");
                } else {
                    builder.append("          <td colspan=\"5\" align=\"center\">no records found</td>\n");
                }
                builder.append("        </tr>\n");
            } else {
                DateFormat dateFormat = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM, locale);
                dateFormat.setTimeZone(timeZone);
                GregorianCalendar calendar = new GregorianCalendar(locale);
                calendar.setTimeZone(timeZone);
                boolean noMore = true;
                for (long timeKey : queryMap.descendingKeySet()) {
                    User.Query query = queryMap.get(timeKey);
                    if (query == null) {
                        calendar.setTimeInMillis(timeKey);
                        noMore = false;
                        builder.append("        <tr id=\"rowMore\" class=\"click\" onclick=\"more('");
                        builder.append(timeKey);
                        builder.append("')\">\n");
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            builder.append("          <td id=\"columnMore\" colspan=\"5\" align=\"center\">clique para ver mais registros antes de ");
                        } else {
                            builder.append("          <td id=\"columnMore\" colspan=\"5\" align=\"center\">click to see more records before ");
                        }
                        String date = dateFormat.format(calendar.getTime());
                        int index = date.indexOf(' ');
                        date = date.substring(0, index);
                        builder.append(date);
                        builder.append("</td>\n");
                        builder.append("        </tr>\n");
                    } else if (begin == null) {
                        boolean highlight = queryMap.lastKey().equals(timeKey);
                        buildQueryRow(locale, timeZone, builder, dateFormat, calendar, timeKey, query, highlight);
                    } else {
                        buildQueryRow(locale, timeZone, builder, dateFormat, calendar, timeKey, query, false);
                    }
                }
                if (noMore) {
                    builder.append("        <tr>\n");
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("          <td colspan=\"5\" align=\"center\">não foram encontrados outros registros</td>\n");
                    } else {
                        builder.append("          <td colspan=\"5\" align=\"center\">no more records found</td>\n");
                    }
                    builder.append("        </tr>\n");
                }
            }
        }
        return builder.toString();
    }

    public static boolean sendCertificateExpirationAlert(String hostname) {
        String adminEmail = Core.getAdminEmail();
        if (adminEmail == null) {
            return false;
        } else if (hostname == null) {
            return false;
        } else if (!Core.hasOutputSMTP()) {
            return false;
        } else if (NoReply.isUnsubscribed(adminEmail)) {
            return false;
        } else {
            try {
                Locale locale;
                User user = User.get(adminEmail);
                if (user == null) {
                    locale = Core.getDefaultLocale(adminEmail);
                } else {
                    locale = user.getLocale();
                }
                InternetAddress[] recipients = InternetAddress.parse(adminEmail);
                MimeMessage message = Core.newMessage(true);
                message.addRecipients(Message.RecipientType.TO, recipients);
                String subject;
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    subject = "Alerta de expiração iminente de certificado";
                } else {
                    subject = "Imminent certificate expiration alert";
                }
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
                loadStyleCSS(builder);
                builder.append("  </head>\n");
                builder.append("  <body>\n");
                builder.append("    <div id=\"container\">\n");
                builder.append("      <div id=\"divlogo\">\n");
                builder.append("        <img src=\"cid:logo\">\n");
                builder.append("      </div>\n");
                buildMessage(builder, subject);
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "O certificado digital do domínio " + hostname + " está prestes a expirar.");
                    buildText(builder, "Por favor, atualize os arquivos do certificado deste domínio.");
                } else {
                    buildText(builder, "The digital certificate of the domain " + hostname + " is about to expire.");
                    buildText(builder, "Please update the certificate files for this domain.");
                }
                buildFooter(builder, locale, Core.getListUnsubscribeURL(locale, recipients[0]));
                builder.append("    </div>\n");
                builder.append("  </body>\n");
                builder.append("</html>\n");
                // Making HTML part.
                MimeBodyPart htmlPart = new MimeBodyPart();
                htmlPart.setContent(builder.toString(), "text/html;charset=UTF-8");
                // Making logo part.
                MimeBodyPart logoPart = new MimeBodyPart();
                File logoFile = Core.getLogoFile(user);
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
                return ServerSMTP.sendMessage(locale, message, recipients, null);
            } catch (MailConnectException ex) {
                return false;
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        }
    }

    public static boolean loadStyleCSS(
            StringBuilder builder
    ) {
        File styleFile = getWebFile("style.css");
        if (styleFile == null) {
            return false;
        } else {
            try {
                try (BufferedReader reader = new BufferedReader(new FileReader(styleFile))) {
                    builder.append("    <style>\n");
                    String line;
                    while ((line = reader.readLine()) != null) {
                        builder.append("      ");
                        builder.append(line);
                        builder.append('\n');
                    }
                    builder.append("    </style>\n");
                }
                return true;
            } catch (Exception ex) {
                return false;
            }
        }
    }

    private static void buildHead(
            boolean hasRecaptcha,
            StringBuilder builder,
            String title
    ) {
        builder.append("  <head>\n");
        builder.append("    <meta charset=\"UTF-8\">\n");
        builder.append("    <link rel=\"shortcut icon\" type=\"image/png\" href=\"favicon.png\">\n");
        builder.append("    <title>");
        builder.append(title);
        builder.append("</title>\n");
        builder.append("    <link rel=\"stylesheet\" href=\"style.css\">\n");
        if (hasRecaptcha && Core.hasRecaptchaKeys()) {
            // novo reCAPCHA
            builder.append("    <script type=\"text/javascript\">\n");
            builder.append("      function btngoClick() {\n");
            builder.append("        document.getElementById(\"btngo\").click();\n");
            builder.append("      }\n");
            builder.append("    </script>\n");
            builder.append("    <script src=\"https://www.google.com/recaptcha/api.js\" async defer></script>\n");
        }
        builder.append("  </head>\n");
    }

    private static void buildHead(
            StringBuilder builder,
            String title,
            String page,
            int time
    ) {
        builder.append("  <head>\n");
        builder.append("    <meta charset=\"UTF-8\">\n");
        builder.append("    <link rel=\"shortcut icon\" type=\"image/png\" href=\"favicon.png\">\n");
        builder.append("    <meta charset=\"UTF-8\" http-equiv=\"refresh\" content=\"");
        builder.append(time);
        builder.append(";url=");
        builder.append(page);
        builder.append("\">\n");
        if (title != null) {
            builder.append("    <title>");
            builder.append(title);
            builder.append("</title>\n");
        }
        builder.append("    <link rel=\"stylesheet\" href=\"style.css\">\n");
        builder.append("  </head>\n");
    }

    private static void buildLogo(
            StringBuilder builder
    ) {
        builder.append("      <div id=\"divlogo\">\n");
        builder.append("        <img src=\"logo.png\" alt=\"Logo\" style=\"max-width:468px;max-height:60px;\">\n");
        builder.append("      </div>\n");
    }

    private static void buildProcessing(
            StringBuilder builder
    ) {
        builder.append("      <div id=\"divlogo\">\n");
        builder.append("        <img src=\"processing.gif\" alt=\"Processing\" style=\"max-width:468px;max-height:60px;\">\n");
        builder.append("      </div>\n");
    }

    private static void buildAdvertise(
            StringBuilder builder
    ) {
        if (Core.showAdvertisement()) {
            builder.append("      <iframe data-aa='455818' src='//ad.a-ads.com/455818?size=468x60' scrolling='no' style='width:468px; height:60px; border:0px; padding:0;overflow:hidden' allowtransparency='true'></iframe>");
        } else {
            buildLogo(builder);
        }
    }

    public static void buildMessage(
            StringBuilder builder,
            String message
    ) {
        builder.append("      <hr>\n");
        builder.append("      <div id=\"divmsg\">\n");
        builder.append("        <p id=\"titulo\">");
        builder.append(message);
        builder.append("</p>\n");
        builder.append("      </div>\n");
    }

    public static void buildMessage(
            StringBuilder builder,
            Locale locale,
            String message
    ) {
        builder.append("      <hr>\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("      <button onclick=\"window.location='/pt/';\">Nova consulta</button>\n");
        } else {
            builder.append("      <button onclick=\"window.location='/en/';\">New query</button>\n");
        }
        builder.append("      <div id=\"divmsg\">\n");
        builder.append("        <p id=\"titulo\">");
        builder.append(message);
        builder.append("</p>\n");
        builder.append("      </div>\n");
    }

    public static void buildText(
            StringBuilder builder,
            String message
    ) {
        builder.append("      <div id=\"divtexto\">\n");
        StringTokenizer tokenizer = new StringTokenizer(message, "\n");
        while (tokenizer.hasMoreTokens()) {
            String line = tokenizer.nextToken();
            builder.append("        <p>");
            builder.append(line);
            builder.append("</p>\n");
        }
        builder.append("      </div>\n");
    }

    public static void buildConfirmAction(
            StringBuilder builder,
            String name,
            String url,
            String description,
            String publisher,
            String website
    ) {
        builder.append("    <script type=\"application/ld+json\">\n");
        builder.append("    {\n");
        builder.append("      \"@context\": \"http://schema.org\",\n");
        builder.append("      \"@type\": \"EmailMessage\",\n");
        builder.append("      \"potentialAction\": {\n");
        builder.append("        \"@type\": \"ViewAction\",\n");
        builder.append("        \"target\": \"" + url + "\",\n");
        builder.append("        \"url\": \"" + url + "\",\n");
        builder.append("        \"name\": \"" + name + "\"\n");
        builder.append("      },\n");
        builder.append("      \"description\": \"" + description + "\",\n");
        builder.append("      \"publisher\": {\n");
        builder.append("        \"@type\": \"Organization\",\n");
        builder.append("        \"name\": \"" + publisher + "\",\n");
        builder.append("        \"url\": \"" + website + "\"\n");
        builder.append("      }\n");
        builder.append("    }\n");
        builder.append("    </script>\n");
    }

    public static void buildFooter(
            StringBuilder builder,
            Locale locale,
            String unsubscribeURL
    ) {
        builder.append("      <hr>\n");
        builder.append("      <div id=\"divfooter\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            if (unsubscribeURL == null) {
                builder.append("        <div id=\"divanuncio\">\n");
                builder.append("          Obtenha seu <a target=\"_blank\" href='https://spfbl.net/firewall/'>SPAM firewall</a>\n");
                builder.append("        </div>\n");
            } else {
                builder.append("        <div id=\"divanuncio\">\n");
                builder.append("          <a target=\"_blank\" href='");
                builder.append(unsubscribeURL);
                builder.append("'>Cancelar inscrição</a>\n");
                builder.append("        </div>\n");
            }
            builder.append("        <div id=\"divpowered\">\n");
            builder.append("          Powered by <a target=\"_blank\" href=\"http://spfbl.net/\">SPFBL.net</a>\n");
            builder.append("        </div>\n");
        } else {
            if (unsubscribeURL == null) {
                builder.append("        <div id=\"divanuncio\">\n");
                builder.append("          Get your <a target=\"_blank\" href='https://spfbl.net/en/firewall/'>SPAM firewall</a>\n");
                builder.append("        </div>\n");
            } else {
                builder.append("        <div id=\"divanuncio\">\n");
                builder.append("          <a target=\"_blank\" href='");
                builder.append(unsubscribeURL);
                builder.append("'>Unsubscribe</a>\n");
                builder.append("        </div>\n");
            }
            builder.append("        <div id=\"divpowered\">\n");
            builder.append("          Powered by <a target=\"_blank\" href=\"http://spfbl.net/en/\">SPFBL.net</a>\n");
            builder.append("        </div>\n");
        }
        builder.append("      </div>\n");
    }

    private static String getMainHTML(
            Locale locale,
            String message,
            String value
    ) {
        StringBuilder builder = new StringBuilder();
        builder.append("<!DOCTYPE html>\n");
        builder.append("<html lang=\"");
        builder.append(locale.getLanguage());
        builder.append("\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            buildHead(true, builder, "Serviço SPFBL");
        } else {
            buildHead(true, builder, "SPFBL Service");
        }
        builder.append("  <body>\n");
        builder.append("    <div id=\"container\">\n");
        buildLogo(builder);
        buildMessage(builder, message);
        if (Core.hasPortDNSBL()) {
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "Para consultar uma reputação no serviço SPFBL, digite um IP, um FQDN ou uma URL:");
            } else {
                buildText(builder, "To query for reputation in the SPFBL service, type an IP, a FQDN or an URL:");
            }
            builder.append("      <div id=\"divcaptcha\">\n");
            builder.append("        <form method=\"POST\">\n");
            builder.append("          <input type=\"text\" name=\"query\" value=\"");
            builder.append(value);
            builder.append("\" autofocus><br>\n");
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("          <input id=\"btngo\" type=\"submit\" value=\"Consultar\">\n");
            } else {
                builder.append("          <input id=\"btngo\" type=\"submit\" value=\"Query\">\n");
            }
            builder.append("        </form>\n");
            builder.append("      </div>\n");
        } else {
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "Nenhuma ferramenta está disponível neste momento.");
            } else {
                buildText(builder, "No tool is available at this time.");
            }
        }
        buildFooter(builder, locale, null);
        builder.append("    </div>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private String getComplainHMTL(
            Locale locale,
            TreeSet<String> tokenSet,
            TreeSet<String> selectionSet,
            String message,
            boolean writeBlockForm
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<!DOCTYPE html>\n");
        builder.append("<html lang=\"");
        builder.append(locale.getLanguage());
        builder.append("\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            buildHead(true, builder, "Página de denuncia SPFBL");
        } else {
            buildHead(true, builder, "SPFBL complaint page");
        }
        builder.append("  <body>\n");
        builder.append("    <div id=\"container\">\n");
        buildLogo(builder);
        buildMessage(builder, message);
        if (writeBlockForm) {
            writeBlockFormHTML(locale, builder, tokenSet, selectionSet);
        }
        buildFooter(builder, locale, null);
        builder.append("    </div>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private void writeBlockFormHTML(
            Locale locale,
            StringBuilder builder,
            TreeSet<String> tokenSet,
            TreeSet<String> selectionSet
    ) throws ProcessException {
        if (!tokenSet.isEmpty()) {
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "Se você deseja não receber mais mensagens desta origem no futuro, selecione os identificadores que devem ser bloqueados definitivamente:");
            } else {
                buildText(builder, "If you want to stop receiving messages from the source in the future, select identifiers that should definitely be blocked:");
            }
            builder.append("    <form method=\"POST\">\n");
            for (String identifier : tokenSet) {
                builder.append("        <input type=\"checkbox\" name=\"identifier\" value=\"");
                builder.append(identifier);
                if (selectionSet.contains(identifier)) {
                    builder.append("\" checked>");
                } else {
                    builder.append("\">");
                }
                builder.append(identifier);
                builder.append("<br>\n");
            }
            if (Core.hasRecaptchaKeys()) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    buildText(builder, "Para que sua solicitação seja aceita, resolva o desafio reCAPTCHA abaixo.");
                } else {
                    buildText(builder, "For your request to be accepted, please solve the reCAPTCHA below.");
                }
            }
            builder.append("      <div id=\"divcaptcha\">\n");
            buildCaptcha(true, builder);
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("        <input id=\"btngo\" type=\"submit\" value=\"Bloquear\">\n");
            } else {
                builder.append("        <input id=\"btngo\" type=\"submit\" value=\"Block\">\n");
            }
            builder.append("      </div>\n");
            builder.append("    </form>\n");
        }
    }

    private String getComplainHMTL2(
            Locale locale,
            Query query,
            String message
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<!DOCTYPE html>\n");
        builder.append("<html lang=\"");
        builder.append(locale.getLanguage());
        builder.append("\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            buildHead(false, builder, "Página de denuncia SPFBL");
        } else {
            buildHead(false, builder, "SPFBL complaint page");
        }
        builder.append("  <body>\n");
        builder.append("    <div id=\"container\">\n");
        buildLogo(builder);
        buildMessage(builder, message);
        String unsubscribeURL = query == null ? null : query.getUnsubscribeString();
        if (unsubscribeURL != null) {
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "Se você autorizou este remetente a te enviar e-mail, você deve se desinscriever da lista dele por meio deste link:");
            } else {
                buildText(builder, "If you have authorized this sender to send email to you, than you must request unsubscribe through this link:");
            }
            builder.append("    <ul>\n");
            builder.append("    <li><a target=\"_blank\" href=\"");
            builder.append(unsubscribeURL);
            builder.append("\">");
            builder.append(unsubscribeURL);
            builder.append("</a><br>\n");
            builder.append("    </ul>\n");
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                buildText(builder, "Mas se você nunca autorizou este remetente a te enviar e-mail ou você já se desinscreveu da lista dele antes, você pode solicitar o bloqueio definitivo deste remetente.");
            } else {
                buildText(builder, "But if you've never authorized this sender send mail to you or you've already requested unsubscribe, you can request the definitive blockage of this sender.");
            }
        }
        builder.append("    <form method=\"POST\">\n");
        builder.append("      <div id=\"divcaptcha\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            buildText(builder, "<center>Deseja forçar este remetente a parar de enviar e-mail para você?</center>");
        } else {
            buildText(builder, "<center>Do you want to force this sender stop to send mail to you?</center>");
        }
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("        <input id=\"btngo\" type=\"submit\" value=\"Sim, bloqueie este remetente\">\n");
        } else {
            builder.append("        <input id=\"btngo\" type=\"submit\" value=\"Yes, block this sender\">\n");
        }
        builder.append("      </div>\n");
        builder.append("    </form>\n");
        buildFooter(builder, locale, null);
        builder.append("    </div>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private void buildCaptcha(boolean autoClick, StringBuilder builder) {
        if (Core.hasRecaptchaKeys()) {
            builder.append("      <div class=\"g-recaptcha\" data-sitekey=\"");
            builder.append(Core.getRecaptchaKeySite());
            if (autoClick) {
                builder.append("\" data-callback=\"btngoClick\"></div>\n");
            } else {
                builder.append("\"></div>\n");
            }
        }
    }

    private Boolean validCaptcha(HashMap<String, Object> parameterMap) {
        if (Core.hasRecaptchaKeys()) {
            if (parameterMap == null) {
                return false;
            } else if (parameterMap.containsKey("g-recaptcha-response")) {
                String recaptchaResponse = (String) parameterMap.get("g-recaptcha-response");
                return validCaptcha(recaptchaResponse);
            } else {
                // reCAPCHA necessário.
                return false;
            }
        } else {
            return true;
        }
    }

    private final static String USER_AGENT = "Mozilla/5.0";

    private static Boolean validCaptcha(String gRecaptchaResponse) {
        if (gRecaptchaResponse == null) {
            return false;
        } else if (gRecaptchaResponse.length() == 0) {
            return false;
        } else {
            try {
                URL url = new URL("https://www.google.com/recaptcha/api/siteverify");
                HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
                con.setConnectTimeout(3000);
                con.setReadTimeout(3000);
                con.setRequestMethod("POST");
                con.setRequestProperty("User-Agent", USER_AGENT);
                con.setRequestProperty("Accept-Language", "en-US,en;q=0.5");
                String postParams = "secret=" + Core.getRecaptchaKeySecret() + ""
                        + "&response=" + gRecaptchaResponse;
                con.setDoOutput(true);
                try (DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {
                    wr.writeBytes(postParams);
                    wr.flush();
                }
                StringBuilder response;
                try (BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
                    String inputLine;
                    response = new StringBuilder();
                    while ((inputLine = in.readLine()) != null) {
                        response.append(inputLine);
                    }
                }
                JsonObject jsonObject;
                try (JsonReader jsonReader = Json.createReader(new StringReader(response.toString()))) {
                    jsonObject = jsonReader.readObject();
                }
                return jsonObject.getBoolean("success");
            } catch (SocketTimeoutException ex) {
                return null;
            } catch (UnknownHostException ex) {
                return null;
            } catch (Exception ex) {
                Server.logError(ex);
                return null;
            }
        }
    }

    private static void response(
            int code,
            String type,
            String response,
            HttpExchange exchange
    ) throws IOException {
        byte[] byteArray = response.getBytes("UTF-8");
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", type);
        headers.set("Cache-Control", "no-cache, no-store, must-revalidate"); // HTTP 1.1.
        headers.set("Pragma", "no-cache"); // HTTP 1.0.
        exchange.sendResponseHeaders(code, byteArray.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(byteArray);
        }
    }

    private final BinarySemaphore STARTED = new BinarySemaphore(false);

    public void waitStart() {
        STARTED.acquire();
        STARTED.release(true);
    }

    @Override
    public void start() {
        STARTED.acquire();
        super.start();
    }

    public int getServiceHTTPS() {
        if (SERVERS == null) {
            return 0;
        } else {
            return PORTS;
        }
    }

    /**
     * Inicialização do serviço.
     */
    @Override
    public void run() {
        SERVER.start();
        STARTED.release(true);
        Server.logInfo("listening on HTTP port " + PORT + ".");
        if (PORTS > 0) {
            try {
                KeyStore keyStore = Core.loadKeyStore(HOSTNAME);
                if (keyStore == null) {
                    Server.logError("HTTPS socket was not binded because " + HOSTNAME + " keystore not exists.");
                } else {
                    KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                    kmf.init(keyStore, HOSTNAME.toCharArray());
                    KeyManager[] km = kmf.getKeyManagers();
                    TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
                    tmf.init(keyStore);
                    TrustManager[] tm = tmf.getTrustManagers();
                    SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
                    sslContext.init(km, tm, null);
                    try {
                        Server.logInfo("binding HTTPS socket on port " + PORTS + "...");
                        HttpsServer server = HttpsServer.create(new InetSocketAddress(PORTS), 0);
                        SNIHostName serverName = new SNIHostName(HOSTNAME);
                        final ArrayList<SNIServerName> serverNames = new ArrayList<>(1);
                        serverNames.add(serverName);
                        server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
                            @Override
                            public void configure(HttpsParameters params) {
                                try {
                                    InetSocketAddress clientAddress = params.getClientAddress();
                                    boolean clientAuth = Peer.has(clientAddress.getAddress());
                                    params.setNeedClientAuth(false);
                                    params.setWantClientAuth(clientAuth);

                                    SSLContext c = SSLContext.getDefault();
                                    params.setProtocols(new String[]{"TLSv1.2"});
                                    params.setCipherSuites(new String[]{
                                        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                                        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                                        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
                                        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
                                        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                                        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                                        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                                        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                                        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                                        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
                                    });
                                    SSLParameters sslParameters = c.getDefaultSSLParameters();
                                    sslParameters.setServerNames(serverNames);
                                    sslParameters.setNeedClientAuth(clientAuth);
                                } catch (Exception ex) {
                                    Server.logError(ex);
                                }
                            }
                        });
                        server.createContext("/", new AccessHandler(true));
                        server.setExecutor(EXECUTOR);
                        server.start();
                        SERVERS = server;
                        Server.logInfo("listening on HTTPS port " + PORTS + ".");
                    } catch (BindException ex) {
                        Server.logError("HTTPS socket was not binded because TCP port " + PORTS + " is already in use.");
                    }
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }

    @Override
    protected void close() throws Exception {
        EXECUTOR.shutdown();
        Server.logInfo("unbinding HTTP on port " + PORT + "...");
        SERVER.stop(1);
        Server.logInfo("HTTP server closed.");
        if (SERVERS != null) {
            Server.logInfo("unbinding HTTPS on port " + PORTS + "...");
            SERVERS.stop(1);
            Server.logInfo("HTTPS server closed.");
        }
    }
    
    private class ExecutorHTTP implements ExecutorService {
        
        private boolean shutdown = false;
        private boolean terminated = false;

        @Override
        public void shutdown() {
            shutdown = true;
            Connection connection;
            while ((connection = last()) != null) {
                connection.interrupt();
            }
            terminated = true;
        }

        @Override
        public List<Runnable> shutdownNow() {
            shutdown = false;
            LinkedList<Runnable> commandList = new LinkedList<>();
            Connection connection;
            while ((connection = last()) != null) {
                Runnable command = connection.COMMAND;
                connection.interrupt();
                if (command != null) {
                    commandList.addLast(command);
                }
            }
            terminated = true;
            return commandList;
        }

        @Override
        public boolean isShutdown() {
            return shutdown;
        }

        @Override
        public boolean isTerminated() {
            return terminated;
        }

        @Override
        public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
            return true;
        }

        @Override
        public <T> Future<T> submit(Callable<T> task) {
            Server.logError(new UnsupportedOperationException("Not supported yet."));
            return null;
        }

        @Override
        public <T> Future<T> submit(Runnable task, T result) {
            Server.logError(new UnsupportedOperationException("Not supported yet."));
            return null;
        }

        @Override
        public Future<?> submit(Runnable task) {
            Server.logError(new UnsupportedOperationException("Not supported yet."));
            return null;
        }

        @Override
        public <T> List<Future<T>> invokeAll(Collection<? extends Callable<T>> tasks) throws InterruptedException {
            Server.logError(new UnsupportedOperationException("Not supported yet."));
            return null;
        }

        @Override
        public <T> List<Future<T>> invokeAll(Collection<? extends Callable<T>> tasks, long timeout, TimeUnit unit) throws InterruptedException {
            Server.logError(new UnsupportedOperationException("Not supported yet."));
            return null;
        }

        @Override
        public <T> T invokeAny(Collection<? extends Callable<T>> tasks) throws InterruptedException, ExecutionException {
            Server.logError(new UnsupportedOperationException("Not supported yet."));
            return null;
        }

        @Override
        public <T> T invokeAny(Collection<? extends Callable<T>> tasks, long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
            Server.logError(new UnsupportedOperationException("Not supported yet."));
            return null;
        }

        @Override
        public void execute(Runnable command) {
            Thread.currentThread().setName("SERVERHTP");
            Connection connection = pollConnection();
            if (connection == null) {
                command.run();
            } else {
                connection.process(command);
            }
        }
    }
    
    private class Connection extends Thread {
        
        private Runnable COMMAND = null;
        private final Semaphore SEMAPHORE = new Semaphore(0);
        
        public Connection(int id) {
            String name = "HTTP00" + Core.formatCentena(id);
            Server.logInfo("creating " + name + "...");
            setName(name);
            setPriority(Thread.NORM_PRIORITY);
            Server.logTrace(name + " thread allocation.");
        }
        
        public void process(Runnable command) {
            COMMAND = command;
            SEMAPHORE.release();
        }
        
        @Override
        public void interrupt() {
            Server.logInfo("closing " + getName() + "...");
            COMMAND = null;
            SEMAPHORE.release();
        }
        
        public Runnable getCommand() {
            try {
                SEMAPHORE.acquire();
                return COMMAND;
            } catch (InterruptedException ex) {
                Server.logError(ex);
                return null;
            }
        }
        
        @Override
        public void run() {
            try {
                Runnable command;
                while ((command = getCommand()) != null) {
                    try {
                        command.run();
                    } catch (Exception ex) {
                        Server.logError(ex);
                    } finally {
                        offerConnection(this);
                    }
                }
            } finally {
                Server.logTrace(getName() + " thread closed.");
            }
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
                ServerHTTP.this.notify();
                return true;
            } else if (CONNECTION_QUEUE.size() < 2) {
                CONNECTION_QUEUE.offer(connection);
                ServerHTTP.this.notify();
                return true;
            } else if (connection == CONNECTION_LIST.getLast()) {
                connection.interrupt();
                CONNECTION_LIST.removeLast();
                return false;
            } else {
                CONNECTION_QUEUE.offer(connection);
                ServerHTTP.this.notify();
                return true;
            }
        }
    }
    
    private Connection pollConnection() {
        Connection connection = poll();
        if (connection == null) {
            try {
                synchronized (ServerHTTP.this) {
                    ServerHTTP.this.wait(500);
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
}
