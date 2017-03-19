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
package net.spfbl.http;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import net.spfbl.core.Server;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Locale;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.TreeSet;
import javax.mail.Message;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import net.spfbl.data.Block;
import net.spfbl.core.Client;
import static net.spfbl.core.Client.Permission.DNSBL;
import net.spfbl.core.Core;
import net.spfbl.core.Defer;
import net.spfbl.core.ProcessException;
import net.spfbl.core.Reverse;
import net.spfbl.core.User;
import net.spfbl.core.User.Query;
import net.spfbl.core.User.Situation;
import net.spfbl.data.Generic;
import net.spfbl.data.NoReply;
import net.spfbl.data.Provider;
import net.spfbl.data.Trap;
import net.spfbl.data.White;
import net.spfbl.spf.SPF;
import net.spfbl.spf.SPF.Distribution;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import net.tanesha.recaptcha.ReCaptcha;
import net.tanesha.recaptcha.ReCaptchaFactory;
import net.tanesha.recaptcha.ReCaptchaResponse;
import org.apache.commons.lang3.LocaleUtils;
import org.apache.commons.lang3.SerializationUtils;

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
    private final HttpServer SERVER;

    private final HashMap<String,String> MAP = new HashMap<String,String>();

    public synchronized HashMap<String,String> getMap() {
        HashMap<String,String> map = new HashMap<String,String>();
        map.putAll(MAP);
        return map;
    }

    public synchronized String drop(String domain) {
        return MAP.remove(domain);
    }

    public synchronized boolean put(String domain, String url) {
        try {
            domain = Domain.normalizeHostname(domain, false);
            if (domain == null) {
                return false;
            } else if (url == null || url.equals("NONE")) {
                MAP.put(domain, null);
                return true;
            } else {
                new URL(url);
                if (url.endsWith("/spam/")) {
                    MAP.put(domain, url);
                    return true;
                } else {
                    return false;
                }
            }
        } catch (MalformedURLException ex) {
            return false;
        }
    }

    public synchronized void store() {
        try {
            long time = System.currentTimeMillis();
            File file = new File("./data/url.map");
            if (MAP.isEmpty()) {
                file.delete();
            } else {
                FileOutputStream outputStream = new FileOutputStream(file);
                try {
                    SerializationUtils.serialize(MAP, outputStream);
                } finally {
                    outputStream.close();
                }
                Server.logStore(time, file);
            }
        } catch (Exception ex) {
            Server.logError(ex);
        }
    }

    public synchronized void load() {
        long time = System.currentTimeMillis();
        File file = new File("./data/url.map");
        if (file.exists()) {
            try {
                HashMap<String,String> map;
                FileInputStream fileInputStream = new FileInputStream(file);
                try {
                    map = SerializationUtils.deserialize(fileInputStream);
                } finally {
                    fileInputStream.close();
                }
                MAP.putAll(map);
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }

    /**
     * Configuração e intanciamento do servidor.
     * @param port a porta HTTPS a ser vinculada.
     * @throws java.io.IOException se houver falha durante o bind.
     */
    public ServerHTTP(String hostname, int port) throws IOException {
        super("SERVERHTP");
        HOSTNAME = hostname;
        PORT = port;
        setPriority(Thread.NORM_PRIORITY);
        // Criando conexões.
        Server.logDebug("binding HTTP socket on port " + port + "...");
        SERVER = HttpServer.create(new InetSocketAddress(port), 0);
        SERVER.createContext("/", new ComplainHandler());
        SERVER.setExecutor(null); // creates a default executor
        Server.logTrace(getName() + " thread allocation.");
    }
    
    public String getURL() {
        if (HOSTNAME == null) {
            return null;
        } else {
            return "http://" + HOSTNAME + (PORT == 80 ? "" : ":" + PORT) + "/";
        }
    }

    public String getDNSBLURL() {
        if (HOSTNAME == null) {
            return null;
        } else {
            return "http://" + HOSTNAME + (PORT == 80 ? "" : ":" + PORT) + "/dnsbl/";
        }
    }
    
    public synchronized String getSpamURL(String domain) {
        if (MAP.containsKey(domain)) {
            return MAP.get(domain);
        } else if (HOSTNAME == null) {
            return null;
        } else {
            return "http://" + HOSTNAME + (PORT == 80 ? "" : ":" + PORT) + "/spam/";
        }
    }

    private static String getOrigin(String address, Client client, User user) {
        String result = address;
        result += (client == null ? "" : " " + client.getDomain());
        result += (user == null ? "" : " " + user.getEmail());
        return result;
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
        InputStreamReader isr = new InputStreamReader(exchange.getRequestBody(), "UTF-8");
        BufferedReader br = new BufferedReader(isr);
        String query = br.readLine();
        return getParameterMap(query);
    }

    @SuppressWarnings("unchecked")
    private static HashMap<String,Object> getParameterMap(String query) throws UnsupportedEncodingException {
        if (query == null) {
            return new HashMap<String,Object>();
        } else {
            Integer otp = null;
            Long begin = null;
            TreeSet<String> identifierSet = new TreeSet<String>();
            HashMap<String,Object> map = new HashMap<String,Object>();
            String pairs[] = query.split("[&]");
            for (String pair : pairs) {
                String param[] = pair.split("[=]");
                String key = null;
                String value = null;
                if (param.length > 0) {
                    key = URLDecoder.decode(param[0], System.getProperty("file.encoding"));
                }
                if (param.length > 1) {
                    value = URLDecoder.decode(param[1], System.getProperty("file.encoding"));
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
                } else {
                    map.put(key, value);
                }
            }
            if (otp != null) {
                map.put("otp", otp);
            }
            if (begin != null) {
                map.put("begin", begin);
            }
            if (!identifierSet.isEmpty()) {
                map.put("identifier", identifierSet);
            }
            return map;
        }
    }
    
    private static class Language implements Comparable<Language> {
        
        private final Locale locale;
        private float q;
        
        private Language(String language) {
            language = language.replace('-', '_');
            int index = language.indexOf(';');
            if (index == -1) {
                locale = LocaleUtils.toLocale(language);
                q = 1.0f;
            } else {
                String value = language.substring(0,index).trim();
                locale = LocaleUtils.toLocale(value);
                try {
                    index = language.lastIndexOf('=') + 1;
                    value = language.substring(index).trim();
                    q = Float.parseFloat(value);
                } catch (NumberFormatException ex) {
                    q = 0.0f;
                }
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
            TreeSet<Language> languageSet = new TreeSet<Language>();
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
    
    private static User getUser(HttpExchange exchange) {
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
                            InetAddress ticketAddress = InetAddress.getByName(tokenizer2.nextToken());
                            if (exchange.getRemoteAddress().getAddress().equals(ticketAddress)) {
                                return User.get(email);
                            }
                        }
                    }
                } catch (Exception ex) {
                    // Nada deve ser feito.
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
        Headers headers = exchange.getResponseHeaders();
        InetAddress remoteAddress = exchange.getRemoteAddress().getAddress();
        String registry = Server.getNewTicketDate() + " " + user.getEmail() + " " + remoteAddress.getHostAddress();
        String ticket = Server.encrypt(registry);
        String cookie = "login=" + ticket + "; expires=" + getDateExpiresCookie() + "; path=/";
        headers.add("Set-Cookie", cookie);
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

    private static class ComplainHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) {
            try {
                long time = System.currentTimeMillis();
                Thread.currentThread().setName("HTTPCMMND");
                String request = exchange.getRequestMethod();
                URI uri = exchange.getRequestURI();
                String command = uri.toString();
                Locale locale = getLocale(exchange);
                User user = getUser(exchange);
                Client client = getClient(exchange);
                String remoteAddress = getRemoteAddress(exchange);
                String origin = getOrigin(remoteAddress, client, user);
                command = URLDecoder.decode(command, "UTF-8");
                Server.logTrace(request + " " + command);
                int code;
                String result;
                String type;
                if (client != null && client.addQuery() && client.isAbusing()) {
                    type = "ABUSE";
                    code = 500;
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        result = "O CIDR " + client.getCIDR() + " foi banido por abuso.";
                    } else {
                        result = "The CIDR " + client.getCIDR() + " is banned by abuse.";
                    }
                } else if (!Core.hasHostname()) {
                    type = "ERROR";
                    code = 500;
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        result = getMessageHMTL(
                                "Página de erro do SPFBL",
                                "O hostname deste sistema não foi definido no arquivo de configuração."
                        );
                    } else {
                        result = getMessageHMTL(
                                "SPFBL error page",
                                "The hostname of this system has not been defined in the configuration file."
                        );
                    }
                } else if (request.equals("POST")) {
                    if (command.equals("/")) {
                        type = "MMENU";
                        code = 200;
                        String message;
                        HashMap<String,Object> parameterMap = getParameterMap(exchange);
                        if (parameterMap.containsKey("query")) {
                            String query = (String) parameterMap.get("query");
                            if (Subnet.isValidIP(query) || Domain.isHostname(query)) {
                                String url = Core.getDNSBLURL(query);
                                result = getRedirectHTML(url);
                            } else {
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    message = "Consulta inválida.";
                                } else {
                                    message = "Invalid query.";
                                }
                                result = getMainHTML(locale, message, remoteAddress);
                            }
                        } else {
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                message = "Este é página principal do serviço SPFBL.";
                            } else {
                                message = "This is SPFBL's main page.";
                            }
                            result = getMainHTML(locale, message, remoteAddress);
                        }
                    } else if (Domain.isEmail(command.substring(1))) {
                        String message;
                        String userEmail = command.substring(1).toLowerCase();
                        User userLogin = getUser(exchange);
                        if (userLogin != null && userLogin.isEmail(userEmail)) {
                            HashMap<String,Object> parameterMap = getParameterMap(exchange);
                            Long begin = (Long) parameterMap.get("begin");
                            message = getControlPanel(locale, userLogin, begin);
//                            message = getRedirectHTML(command);
                        } else if ((userLogin = User.get(userEmail)) == null) {
                            message = getMessageHMTL(
                                    "Login do SPFBL",
                                    "Usuário inexistente."
                            );
                        } else if (userLogin.hasSecretOTP() || userLogin.hasTransitionOTP()) {
                            HashMap<String,Object> parameterMap = getParameterMap(exchange);
                            if (parameterMap.containsKey("otp")) {
                                Integer otp = (Integer) parameterMap.get("otp");
                                if (userLogin.isValidOTP(otp)) {
                                    setUser(exchange, userLogin);
                                    message = getRedirectHTML(command);
                                } else if (userLogin.tooManyFails()) {
                                    long failTime = userLogin.getFailTime();
                                    int pageTime = (int) (failTime / 1000) + 1;
                                    String tempoPunicao = getTempoPunicao(failTime);
                                    message = getRedirectHMTL(
                                            "Login do SPFBL",
                                            "Conta temporariamente bloqueada por excesso de logins fracassados.\n"
                                            + "Aguarde cerca de " + tempoPunicao + " para tentar novamente.",
                                            command,
                                            pageTime
                                    );
                                } else if (userLogin.hasTransitionOTP()) {
                                    if (userLogin.hasSecretOTP()) {
                                        message = getLoginOTPHMTL(
                                                locale,
                                                "Para confirmar a mudança de senha TOTP,\n"
                                                + "digite o valor da nova chave enviada por e-mail:"
                                        );
                                    } else {
                                        message = getLoginOTPHMTL(
                                                locale,
                                                "Para ativar a senha TOTP da sua conta,\n"
                                                + "digite o valor da chave enviada por e-mail:"
                                        );
                                    }
                                } else {
                                    message = getLoginOTPHMTL(
                                            locale,
                                            "A senha TOTP inserida é inválida para esta conta.\n"
                                            + "Para ativar a autenticação TOTP da sua conta,\n"
                                            + "digite o valor da chave enviada por e-mail:"
                                    );
                                }
                            } else {
                                message = getLoginOTPHMTL(
                                        locale,
                                        "Para entrar no painel de controle,\n"
                                        + "digite o valor da chave TOTP de sua conta:"
                                );
                            }
                        } else {
                            HashMap<String,Object> parameterMap = getParameterMap(exchange);
                            boolean valid = true;
                            if (Core.hasRecaptchaKeys()) {
                                if (parameterMap.containsKey("recaptcha_challenge_field")
                                        && parameterMap.containsKey("recaptcha_response_field")
                                        ) {
                                    // reCAPCHA convencional.
                                    String recaptchaPublicKey = Core.getRecaptchaKeySite();
                                    String recaptchaPrivateKey = Core.getRecaptchaKeySecret();
                                    ReCaptcha captcha = ReCaptchaFactory.newReCaptcha(recaptchaPublicKey, recaptchaPrivateKey, true);
                                    String recaptchaChallenge = (String) parameterMap.get("recaptcha_challenge_field");
                                    String recaptchaResponse = (String) parameterMap.get("recaptcha_response_field");
                                    if (recaptchaResponse == null) {
                                        valid = false;
                                    } else {
                                        ReCaptchaResponse response = captcha.checkAnswer(remoteAddress, recaptchaChallenge, recaptchaResponse);
                                        valid = response.isValid();
                                    }
                                } else if (parameterMap.containsKey("g-recaptcha-response")) {
                                    // TODO: novo reCAPCHA.
                                    valid = false;
                                } else {
                                    // reCAPCHA necessário.
                                    valid = false;
                                }
                            }
                            if (valid) {
                                if (enviarOTP(locale, userLogin)) {
                                    message = getLoginOTPHMTL(
                                            locale,
                                            "Segredo TOTP enviado com sucesso.\n"
                                            + "Para confirmar a mudança de senha TOTP,\n"
                                            + "digite o valor do segredo enviado por e-mail:"
                                    );
                                } else {
                                    message = getMessageHMTL(
                                            "Login do SPFBL",
                                            "Não foi possível enviar o segredo TOTP."
                                    );
                                }
                            } else {
                                message = getSendOTPHMTL(
                                        locale,
                                        "Para receber o segredo TOTP em seu e-mail,\n"
                                        + "resolva o reCAPTCHA abaixo."
                                );
                            }
                        }
                        type = "PANEL";
                        code = 200;
                        result = message;
                    } else if (Core.isLong(command.substring(1))) {
                        User userLogin = getUser(exchange);
                        if (userLogin == null) {
                            type = "QUERY";
                            code = 403;
                            result = "Forbidden\n";
                        } else {
                            long queryTime = Long.parseLong(command.substring(1));
                            User.Query query = userLogin.getQuery(queryTime);
                            if (query == null) {
                                type = "QUERY";
                                code = 403;
                                result = "Forbidden\n";
                            } else {
                                type = "QUERY";
                                code = 200;
                                HashMap<String,Object> parameterMap = getParameterMap(exchange);
                                if (parameterMap.containsKey("POLICY")) {
                                    String policy = (String) parameterMap.get("POLICY");
                                    if (policy.startsWith("WHITE_")) {
                                        query.white(queryTime, policy.substring(6));
                                        query.processComplainForWhite();
                                    } else if (policy.startsWith("BLOCK_")) {
                                        query.block(queryTime, policy.substring(6));
                                        query.processComplainForBlock();
                                    }
                                }
                                result = getControlPanel(locale, query, queryTime);
                            }
                        }
                    } else if (command.startsWith("/dnsbl/")) {
                        String title;
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            title = "Página de checagem DNSBL";
                        } else {
                            title = "DNSBL check page";
                        }
                        int index = command.indexOf('/', 1) + 1;
                        String ip = command.substring(index);
                        if (Subnet.isValidIP(ip)) {
                            HashMap<String,Object> parameterMap = getParameterMap(exchange);
                            if (parameterMap.containsKey("identifier")) {
                                boolean valid = true;
                                if (Core.hasRecaptchaKeys()) {
                                    if (parameterMap.containsKey("recaptcha_challenge_field")
                                            && parameterMap.containsKey("recaptcha_response_field")
                                            ) {
                                        // reCAPCHA convencional.
                                        String recaptchaPublicKey = Core.getRecaptchaKeySite();
                                        String recaptchaPrivateKey = Core.getRecaptchaKeySecret();
                                        ReCaptcha captcha = ReCaptchaFactory.newReCaptcha(recaptchaPublicKey, recaptchaPrivateKey, true);
                                        String recaptchaChallenge = (String) parameterMap.get("recaptcha_challenge_field");
                                        String recaptchaResponse = (String) parameterMap.get("recaptcha_response_field");
                                        if (recaptchaResponse == null) {
                                            valid = false;
                                        } else {
                                            ReCaptchaResponse response = captcha.checkAnswer(remoteAddress, recaptchaChallenge, recaptchaResponse);
                                            valid = response.isValid();
                                        }
                                    } else if (parameterMap.containsKey("g-recaptcha-response")) {
                                        // TODO: novo reCAPCHA.
                                        valid = false;
                                    } else {
                                        // reCAPCHA necessário.
                                        valid = false;
                                    }
                                }
                                if (valid) {
                                    String message;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        message = "Chave de desbloqueio não pode ser enviada\n"
                                                + "devido a um erro interno.";
                                    } else {
                                        message = "Unblocking key can not be sent\n"
                                                + "due to an internal error.";
                                    }
                                    TreeSet<String> postmaterSet = getPostmaterSet(ip);
                                    if (
                                            client != null &&
                                            client.hasPermission(DNSBL) &&
                                            client.hasEmail()
                                            ) {
                                        postmaterSet.add(client.getEmail());
                                    }
                                    TreeSet<String> emailSet = (TreeSet<String>) parameterMap.get("identifier");
                                    for (String email : emailSet) {
                                        if (postmaterSet.contains(email)) {
                                            String url = Core.getUnblockURL(email, ip);
                                            if (enviarDesbloqueioDNSBL(locale, url, ip, email)) {
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Chave de desbloqueio enviada com sucesso.";
                                                } else {
                                                    message = "Unblocking key successfully sent.";
                                                }
                                            }
                                        }
                                    }
                                    type = "DNSBL";
                                    code = 200;
                                    result = getMessageHMTL(title, message);
                                } else {
                                    type = "DNSBL";
                                    code = 200;
                                    String message;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        message = "O desafio do reCAPTCHA não foi resolvido.";
                                    } else {
                                        message = "The reCAPTCHA challenge has not been resolved.";
                                    }
                                    result = getDNSBLHTML(locale, client, ip, message);
                                }
                            } else {
                                type = "DNSBL";
                                code = 200;
                                String message;
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    message = "O e-mail do responsável pelo IP não foi definido.";
                                } else {
                                    message = "The e-mail of responsible IP was not set.";
                                }
                                result = getDNSBLHTML(locale, client, ip, message);
                            }
                        } else {
                            type = "DNSBL";
                            code = 500;
                            String message;
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                message = "O identificador informado não é um IP nem um domínio válido.";
                            } else {
                                message = "Informed identifier is not a valid IP or a valid domain.";
                            }
                            result = getMessageHMTL(title, message);
                        }
                    } else if (command.startsWith("/spam/")) {
                        try {
                            int index = command.indexOf('/', 1) + 1;
                            String ticket = command.substring(index);
                            ticket = URLDecoder.decode(ticket, "UTF-8");
                            String recipient = SPF.getRecipient(ticket);
                            String clientTicket = SPF.getClient(ticket);
                            clientTicket = clientTicket == null ? "" : clientTicket + ':';
                            HashMap<String,Object> parameterMap = getParameterMap(exchange);
                            if (parameterMap.containsKey("identifier")) {
                                boolean valid = true;
                                TreeSet<String> identifierSet = (TreeSet<String>) parameterMap.get("identifier");
                                if (Core.hasRecaptchaKeys()) {
                                    if (parameterMap.containsKey("recaptcha_challenge_field")
                                            && parameterMap.containsKey("recaptcha_response_field")
                                            ) {
                                        // reCAPCHA convencional.
                                        String recaptchaPublicKey = Core.getRecaptchaKeySite();
                                        String recaptchaPrivateKey = Core.getRecaptchaKeySecret();
                                        ReCaptcha captcha = ReCaptchaFactory.newReCaptcha(recaptchaPublicKey, recaptchaPrivateKey, true);
                                        String recaptchaChallenge = (String) parameterMap.get("recaptcha_challenge_field");
                                        String recaptchaResponse = (String) parameterMap.get("recaptcha_response_field");
                                        if (recaptchaResponse == null) {
                                            valid = false;
                                        } else {
                                            ReCaptchaResponse response = captcha.checkAnswer(remoteAddress, recaptchaChallenge, recaptchaResponse);
                                            valid = response.isValid();
                                        }
                                    } else if (parameterMap.containsKey("g-recaptcha-response")) {
                                        // TODO: novo reCAPCHA.
                                        valid = false;
                                    } else {
                                        // reCAPCHA necessário.
                                        valid = false;
                                    }
                                }
                                TreeSet<String> tokenSet = SPF.getTokenSet(ticket);
                                tokenSet = SPF.expandTokenSet(tokenSet);
                                if (valid) {
                                    TreeSet<String> blockSet = new TreeSet<String>();
                                    for (String identifier : identifierSet) {
                                        if (tokenSet.contains(identifier)) {
                                            long time2 = System.currentTimeMillis();
                                            String block = clientTicket + identifier + '>' + recipient;
                                            if (Block.addExact(block)) {
                                                Server.logQuery(
                                                        time2, "BLOCK",
                                                        origin,
                                                        "BLOCK ADD " + block,
                                                        "ADDED"
                                                        );
                                            }
                                            blockSet.add(identifier);
                                        }
                                    }
                                    type = "HTTPC";
                                    code = 200;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        result = "Bloqueados: " + blockSet + " >" + recipient + "\n";
                                    } else {
                                        result = "Blocked: " + blockSet + " >" + recipient + "\n";
                                    }
                                } else {
                                    type = "HTTPC";
                                    code = 200;
                                    String message;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        message = "O desafio do reCAPTCHA não foi resolvido.";
                                    } else {
                                        message = "The CAPTCHA challenge has not been resolved.";
                                    }
                                    result = getComplainHMTL(locale, tokenSet, identifierSet, message, true);
                                }
                            } else {
                                type = "HTTPC";
                                code = 500;
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    result = "Identificadores indefinidos.\n";
                                } else {
                                    result = "Undefined identifiers.\n";
                                }
                            }
                        } catch (Exception ex) {
                            type = "HTTPC";
                            code = 500;
                            result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                        }
                    } else if (command.startsWith("/release/")) {
                        String title;
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            title = "Página de liberação do SPFBL";
                        } else {
                            title = "SPFBL release page";
                        }
                        try {
                            int index = command.indexOf('/', 1) + 1;
                            String ticket = command.substring(index);
                            ticket = URLDecoder.decode(ticket, "UTF-8");
                            String registry = Server.decrypt(ticket);
                            index = registry.indexOf(' ');
                            Date date = Server.parseTicketDate(registry.substring(0, index));
                            if (System.currentTimeMillis() - date.getTime() > 432000000) {
                                // Ticket vencido com mais de 5 dias.
                                type = "DEFER";
                                code = 500;
                                 String message;
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    message = "Este ticket de liberação está vencido.";
                                } else {
                                    message = "This release ticket is expired.";
                                }
                                result = getMessageHMTL(title, message);
                            } else {
                                boolean valid = true;
                                if (Core.hasRecaptchaKeys()) {
                                    HashMap<String,Object> parameterMap = getParameterMap(exchange);
                                    if (parameterMap.containsKey("recaptcha_challenge_field")
                                            && parameterMap.containsKey("recaptcha_response_field")
                                            ) {
                                        // reCAPCHA convencional.
                                        String recaptchaPublicKey = Core.getRecaptchaKeySite();
                                        String recaptchaPrivateKey = Core.getRecaptchaKeySecret();
                                        ReCaptcha captcha = ReCaptchaFactory.newReCaptcha(recaptchaPublicKey, recaptchaPrivateKey, true);
                                        String recaptchaChallenge = (String) parameterMap.get("recaptcha_challenge_field");
                                        String recaptchaResponse = (String) parameterMap.get("recaptcha_response_field");
                                        if (recaptchaResponse == null) {
                                            valid = false;
                                        } else {
                                            ReCaptchaResponse response = captcha.checkAnswer(remoteAddress, recaptchaChallenge, recaptchaResponse);
                                            valid = response.isValid();
                                        }
                                    } else if (parameterMap.containsKey("g-recaptcha-response")) {
                                        // TODO: novo reCAPCHA.
                                        valid = false;
                                    } else {
                                        // reCAPCHA necessário.
                                        valid = false;
                                    }
                                }
                                if (valid) {
                                    String id = registry.substring(index + 1);
                                    String message;
                                    if (Defer.release(id)) {
                                        String clientTicket = SPF.getClient(ticket);
                                        String sender = SPF.getSender(ticket);
                                        String recipient = SPF.getRecipient(ticket);
                                        if (clientTicket != null && sender != null && recipient != null) {
                                            if (White.addExact(clientTicket + ":" + sender + ";PASS>" + recipient)) {
                                                Server.logDebug("WHITE ADD " + clientTicket + ":" + sender + ";PASS>" + recipient);
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
                                    type = "DEFER";
                                    code = 200;
                                    result = getMessageHMTL(title, message);
                                } else {
                                    type = "DEFER";
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
                            }
                        } catch (Exception ex) {
                            type = "SPFSP";
                            code = 500;
                            result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                        }
                    } else if (command.startsWith("/unblock/")) {
                        String title;
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            title = "Página de desbloqueio do SPFBL";
                        } else {
                            title = "SPFBL unblock page";
                        }
                        try {
                            int index = command.indexOf('/', 1) + 1;
                            String ticket = command.substring(index);
                            ticket = URLDecoder.decode(ticket, "UTF-8");
                            String registry = Server.decrypt(ticket);
                            StringTokenizer tokenizer = new StringTokenizer(registry, " ");
                            Date date = Server.parseTicketDate(tokenizer.nextToken());
                            if (System.currentTimeMillis() - date.getTime() > 432000000) {
                                // Ticket vencido com mais de 5 dias.
                                type = "BLOCK";
                                code = 500;
                                String message;
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    message = "Este ticket de desbloqueio está vencido.";
                                } else {
                                    message = "This unblock ticket is expired.";
                                }
                                result = getMessageHMTL(title, message);
                            } else {
                                boolean valid = true;
                                if (Core.hasRecaptchaKeys()) {
                                    HashMap<String,Object> parameterMap = getParameterMap(exchange);
                                    if (parameterMap.containsKey("recaptcha_challenge_field")
                                            && parameterMap.containsKey("recaptcha_response_field")
                                            ) {
                                        // reCAPCHA convencional.
                                        String recaptchaPublicKey = Core.getRecaptchaKeySite();
                                        String recaptchaPrivateKey = Core.getRecaptchaKeySecret();
                                        ReCaptcha captcha = ReCaptchaFactory.newReCaptcha(recaptchaPublicKey, recaptchaPrivateKey, true);
                                        String recaptchaChallenge = (String) parameterMap.get("recaptcha_challenge_field");
                                        String recaptchaResponse = (String) parameterMap.get("recaptcha_response_field");
                                        if (recaptchaResponse == null) {
                                            valid = false;
                                        } else {
                                            ReCaptchaResponse response = captcha.checkAnswer(remoteAddress, recaptchaChallenge, recaptchaResponse);
                                            valid = response.isValid();
                                        }
                                    } else if (parameterMap.containsKey("g-recaptcha-response")) {
                                        // TODO: novo reCAPCHA.
                                        valid = false;
                                    } else {
                                        // reCAPCHA necessário.
                                        valid = false;
                                    }
                                }
                                String clientTicket = tokenizer.nextToken();
                                String ip = tokenizer.nextToken();
                                if (!tokenizer.hasMoreTokens()) {
                                    if (valid) {
                                        String message;
                                        if (Block.clearCIDR(ip, clientTicket)) {
                                            TreeSet<String> tokenSet = Reverse.getPointerSet(ip);
                                            tokenSet.add(clientTicket);
                                            String block;
                                            for (String token : tokenSet) {
                                                while ((block = Block.find(null, null, token, true, true, false)) != null) {
                                                    if (Block.dropExact(block)) {
                                                        Server.logInfo("false positive BLOCK '" + block + "' detected by '" + clientTicket + "'.");
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
                                                message = "O IP " + ip + " já estava desbloqueado.";
                                            } else {
                                                message = "The IP " + ip + " was already unblocked.";
                                            }
                                        }
                                        type = "BLOCK";
                                        code = 200;
                                        result = getMessageHMTL(title, message);
                                    } else {
                                        type = "BLOCK";
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
                                    String sender = tokenizer.nextToken();
                                    String recipient = tokenizer.nextToken();
                                    String hostname = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                                    clientTicket = clientTicket == null ? "" : clientTicket + ':';
                                    String mx = Domain.extractHost(sender, true);
                                    String origem = Provider.containsExact(mx) ? sender : mx;
                                    String white = origem + ">" + recipient;
                                    String url = Core.getWhiteURL(white, clientTicket, ip, sender, hostname, recipient);
                                    String message;
                                    if (enviarDesbloqueio(url, sender, recipient, locale)) {
                                        white = White.normalizeTokenWhite(white);
                                        Block.addExact(white);
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "A solicitação de desbloqueio foi "
                                                    + "enviada para o destinatário '" + recipient + "'.\n"
                                                    + "Aguarde pelo desbloqueio sem enviar novas mensagens.";
                                        } else {
                                            message = "The release request was "
                                                    + "sent to the recipient '" + recipient + "'.\n"
                                                    + "Wait for the release without sending new messages.";
                                        }
                                    } else {
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Não foi possível enviar a solicitação de "
                                                    + "desbloqueio para o destinatário "
                                                    + "'" + recipient + "' devido a problemas técnicos.";
                                        } else {
                                            message = "Could not send the request release to the recipient "
                                                    + "'" + recipient + "' due to technical problems.";
                                        }
                                    }
                                    type = "BLOCK";
                                    code = 200;
                                    result = getMessageHMTL(title, message);
                                } else {
                                    type = "BLOCK";
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
                            }
                        } catch (Exception ex) {
                            type = "SPFSP";
                            code = 500;
                            result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                        }
                    } else if (command.startsWith("/white/")) {
                        String title;
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            title = "Página de desbloqueio do SPFBL";
                        } else {
                            title = "SPFBL unblock page";
                        }
                        try {
                            int index = command.indexOf('/', 1) + 1;
                            String ticket = command.substring(index);
                            ticket = URLDecoder.decode(ticket, "UTF-8");
                            String registry = Server.decrypt(ticket);
                            StringTokenizer tokenizer = new StringTokenizer(registry, " ");
                            Date date = Server.parseTicketDate(tokenizer.nextToken());
                            if (System.currentTimeMillis() - date.getTime() > 432000000) {
                                // Ticket vencido com mais de 5 dias.
                                type = "WHITE";
                                code = 500;
                                String message;
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    message = "Este ticket de desbloqueio está vencido.";
                                } else {
                                    message = "This release ticket is expired.";
                                }
                                result = getMessageHMTL(title, message);
                            } else {
                                boolean valid = true;
                                if (Core.hasRecaptchaKeys()) {
                                    HashMap<String,Object> parameterMap = getParameterMap(exchange);
                                    if (parameterMap.containsKey("recaptcha_challenge_field")
                                            && parameterMap.containsKey("recaptcha_response_field")
                                            ) {
                                        // reCAPCHA convencional.
                                        String recaptchaPublicKey = Core.getRecaptchaKeySite();
                                        String recaptchaPrivateKey = Core.getRecaptchaKeySecret();
                                        ReCaptcha captcha = ReCaptchaFactory.newReCaptcha(recaptchaPublicKey, recaptchaPrivateKey, true);
                                        String recaptchaChallenge = (String) parameterMap.get("recaptcha_challenge_field");
                                        String recaptchaResponse = (String) parameterMap.get("recaptcha_response_field");
                                        if (recaptchaResponse == null) {
                                            valid = false;
                                        } else {
                                            ReCaptchaResponse response = captcha.checkAnswer(remoteAddress, recaptchaChallenge, recaptchaResponse);
                                            valid = response.isValid();
                                        }
                                    } else if (parameterMap.containsKey("g-recaptcha-response")) {
                                        // TODO: novo reCAPCHA.
                                        valid = false;
                                    } else {
                                        // reCAPCHA necessário.
                                        valid = false;
                                    }
                                }
                                if (valid) {
                                    String white = tokenizer.nextToken();
                                    client = Client.getByEmail(tokenizer.nextToken().replace(":", ""));
                                    String ip = tokenizer.nextToken();
                                    String sender = tokenizer.nextToken();
                                    String recipient = tokenizer.nextToken();
                                    String hostname = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                                    String message;
                                    if (White.addExact(white)) {
                                        Block.clear(client, user, ip, sender, hostname, "PASS", recipient);
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "O desbloqueio do remetente '" + sender + "' foi efetuado com sucesso.";
                                        } else {
                                            message = "The unblock of sender '" + sender + "' has been successfully performed.";
                                        }
                                    } else {
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "O desbloqueio do remetente '" + sender + "' já havia sido efetuado.";
                                        } else {
                                            message = "The unblock of sender '" + sender + "' had been made.";
                                        }
                                    }
                                    type = "WHITE";
                                    code = 200;
                                    result = getMessageHMTL(title, message);
                                } else {
                                    type = "WHITE";
                                    code = 200;
                                    String message;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        message = "O desafio reCAPTCHA não foi resolvido. "
                                                + "Tente novamente.";
                                    } else {
                                        message = "The reCAPTCHA challenge was not resolved. "
                                                + "Try again.";
                                    }
                                    result = getWhiteHMTL(locale, message);
                                }
                            }
                        } catch (Exception ex) {
                            type = "SPFSP";
                            code = 500;
                            result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                        }
                    } else if (command.startsWith("/favicon.ico")) {
                        type = "HTTPC";
                        code = 403;
                        result = "Forbidden\n";
                    } else {
                        try {
                            String ticket = command.substring(1);
                            byte[] byteArray = Server.decryptToByteArrayURLSafe(ticket);
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
                                String title;
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    title = "Página do SPFBL";
                                } else {
                                    title = "SPFBL page";
                                }
                                type = "HTTPC";
                                code = 500;
                                String message;
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    message = "Ticket expirado.";
                                } else {
                                    message = "Expired ticket.";
                                }
                                result = getMessageHMTL(title, message);
                            } else {
                                String query = Core.HUFFMAN.decode(byteArray, 8);
                                StringTokenizer tokenizer = new StringTokenizer(query, " ");
                                String operator = tokenizer.nextToken();
                                if (operator.equals("spam")) {
                                    String sender = null;
                                    String recipient = null;
                                    String clientTicket = null;
                                    TreeSet<String> tokenSet = new TreeSet<String>();
                                    while (tokenizer.hasMoreTokens()) {
                                        String token = tokenizer.nextToken();
                                        if (token.startsWith(">") && Domain.isEmail(token.substring(1))) {
                                            recipient = token.substring(1);
                                        } else if (token.endsWith(":") && Domain.isEmail(token.substring(0, token.length() - 1))) {
                                            clientTicket = token.substring(0, token.length() - 1);
                                        } else if (token.startsWith("@") && Domain.isHostname(token.substring(1))) {
                                            sender = token;
                                            tokenSet.add(token);
                                        } else if (Domain.isEmail(token)) {
                                            sender = token;
                                            tokenSet.add(token);
                                        } else {
                                            tokenSet.add(token);
                                        }
                                    }
                                    clientTicket = clientTicket == null ? "" : clientTicket + ':';
                                    HashMap<String, Object> parameterMap = getParameterMap(exchange);
                                    if (parameterMap.containsKey("identifier")) {
                                        boolean valid = true;
                                        TreeSet<String> identifierSet = (TreeSet<String>) parameterMap.get("identifier");
                                        if (Core.hasRecaptchaKeys()) {
                                            if (parameterMap.containsKey("recaptcha_challenge_field")
                                                    && parameterMap.containsKey("recaptcha_response_field")) {
                                                // reCAPCHA convencional.
                                                String recaptchaPublicKey = Core.getRecaptchaKeySite();
                                                String recaptchaPrivateKey = Core.getRecaptchaKeySecret();
                                                ReCaptcha captcha = ReCaptchaFactory.newReCaptcha(recaptchaPublicKey, recaptchaPrivateKey, true);
                                                String recaptchaChallenge = (String) parameterMap.get("recaptcha_challenge_field");
                                                String recaptchaResponse = (String) parameterMap.get("recaptcha_response_field");
                                                if (recaptchaResponse == null) {
                                                    valid = false;
                                                } else {
                                                    ReCaptchaResponse response = captcha.checkAnswer(remoteAddress, recaptchaChallenge, recaptchaResponse);
                                                    valid = response.isValid();
                                                }
                                            } else if (parameterMap.containsKey("g-recaptcha-response")) {
                                                // TODO: novo reCAPCHA.
                                                valid = false;
                                            } else {
                                                // reCAPCHA necessário.
                                                valid = false;
                                            }
                                        }
                                        tokenSet = SPF.expandTokenSet(tokenSet);
                                        if (valid) {
                                            TreeSet<String> blockSet = new TreeSet<String>();
                                            for (String identifier : identifierSet) {
                                                if (tokenSet.contains(identifier)) {
                                                    long time2 = System.currentTimeMillis();
                                                    String block = clientTicket + identifier + '>' + recipient;
                                                    if (Block.addExact(block)) {
                                                        Server.logQuery(
                                                                time2, "BLOCK",
                                                                origin,
                                                                "BLOCK ADD " + block,
                                                                "ADDED"
                                                        );
                                                    }
                                                    blockSet.add(identifier);
                                                }
                                            }
                                            type = "HTTPC";
                                            code = 200;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                result = "Bloqueados: " + blockSet + " >" + recipient + "\n";
                                            } else {
                                                result = "Blocked: " + blockSet + " >" + recipient + "\n";
                                            }
                                        } else {
                                            type = "HTTPC";
                                            code = 200;
                                            String message;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                message = "O desafio do reCAPTCHA não foi resolvido.";
                                            } else {
                                                message = "The CAPTCHA challenge has not been resolved.";
                                            }
                                            result = getComplainHMTL(locale, tokenSet, identifierSet, message, true);
                                        }
                                    } else {
                                        type = "HTTPC";
                                        code = 500;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            result = "Identificadores indefinidos.\n";
                                        } else {
                                            result = "Undefined identifiers.\n";
                                        }
                                    }
                                } else if (operator.equals("unblock")) {
                                    String title;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        title = "Página de desbloqueio do SPFBL";
                                    } else {
                                        title = "SPFBL unblock page";
                                    }
                                    try {
                                        boolean valid = true;
                                        if (Core.hasRecaptchaKeys()) {
                                            HashMap<String,Object> parameterMap = getParameterMap(exchange);
                                            if (parameterMap.containsKey("recaptcha_challenge_field")
                                                    && parameterMap.containsKey("recaptcha_response_field")
                                                    ) {
                                                // reCAPCHA convencional.
                                                String recaptchaPublicKey = Core.getRecaptchaKeySite();
                                                String recaptchaPrivateKey = Core.getRecaptchaKeySecret();
                                                ReCaptcha captcha = ReCaptchaFactory.newReCaptcha(recaptchaPublicKey, recaptchaPrivateKey, true);
                                                String recaptchaChallenge = (String) parameterMap.get("recaptcha_challenge_field");
                                                String recaptchaResponse = (String) parameterMap.get("recaptcha_response_field");
                                                if (recaptchaResponse == null) {
                                                    valid = false;
                                                } else {
                                                    ReCaptchaResponse response = captcha.checkAnswer(remoteAddress, recaptchaChallenge, recaptchaResponse);
                                                    valid = response.isValid();
                                                }
                                            } else if (parameterMap.containsKey("g-recaptcha-response")) {
                                                // TODO: novo reCAPCHA.
                                                valid = false;
                                            } else {
                                                // reCAPCHA necessário.
                                                valid = false;
                                            }
                                        }
                                        String clientTicket = tokenizer.nextToken();
                                        String ip = tokenizer.nextToken();
                                        if (!tokenizer.hasMoreTokens()) {
                                            if (valid) {
                                                String message;
                                                if (Block.clearCIDR(ip, clientTicket)) {
                                                    TreeSet<String> tokenSet = Reverse.getPointerSet(ip);
                                                    tokenSet.add(clientTicket);
                                                    String block;
                                                    for (String token : tokenSet) {
                                                        while ((block = Block.find(null, null, token, true, true, false)) != null) {
                                                            if (Block.dropExact(block)) {
                                                                Server.logInfo("false positive BLOCK '" + block + "' detected by '" + clientTicket + "'.");
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
                                                        message = "O IP " + ip + " já estava desbloqueado.";
                                                    } else {
                                                        message = "The IP " + ip + " was already unblocked.";
                                                    }
                                                }
                                                type = "BLOCK";
                                                code = 200;
                                                result = getMessageHMTL(title, message);
                                            } else {
                                                type = "BLOCK";
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
                                            String sender = tokenizer.nextToken();
                                            String recipient = tokenizer.nextToken();
                                            String hostname = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                                            clientTicket = clientTicket == null ? "" : clientTicket + ':';
                                            String mx = Domain.extractHost(sender, true);
                                            String origem = Provider.containsExact(mx) ? sender : mx;
                                            String white = origem + ">" + recipient;
                                            String url = Core.getWhiteURL(white, clientTicket, ip, sender, hostname, recipient);
                                            String message;
                                            if (enviarDesbloqueio(url, sender, recipient, locale)) {
                                                white = White.normalizeTokenWhite(white);
                                                Block.addExact(white);
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "A solicitação de desbloqueio foi enviada para o destinatário '" + recipient + "'.\n"
                                                            + "A fim de não prejudicar sua reputação, aguarde pelo desbloqueio sem enviar novas mensagens."
                                                            + (NoReply.contains(sender, true) ? "" : "\nVocê receberá uma mensagem deste sistema assim que o destinatário autorizar o recebimento.");
                                                } else {
                                                    message = "The release request was sent to the recipient '" + recipient + "'.\n"
                                                            + "In order not to damage your reputation, wait for the release without sending new messages."
                                                            + (NoReply.contains(sender, true) ? "" : "\nYou will receive a message from this system when the recipient authorize receipt.");
                                                }
                                            } else {
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Não foi possível enviar a solicitação de "
                                                            + "desbloqueio para o destinatário "
                                                            + "'" + recipient + "' devido a problemas técnicos.";
                                                } else {
                                                    message = "Could not send the request release to the recipient "
                                                            + "'" + recipient + "' due to technical problems.";
                                                }
                                            }
                                            type = "BLOCK";
                                            code = 200;
                                            result = getMessageHMTL(title, message);
                                        } else {
                                            type = "BLOCK";
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
                                        type = "SPFSP";
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
                                        boolean valid = true;
                                        if (Core.hasRecaptchaKeys()) {
                                            HashMap<String,Object> parameterMap = getParameterMap(exchange);
                                            if (parameterMap.containsKey("recaptcha_challenge_field")
                                                    && parameterMap.containsKey("recaptcha_response_field")
                                                    ) {
                                                // reCAPCHA convencional.
                                                String recaptchaPublicKey = Core.getRecaptchaKeySite();
                                                String recaptchaPrivateKey = Core.getRecaptchaKeySecret();
                                                ReCaptcha captcha = ReCaptchaFactory.newReCaptcha(recaptchaPublicKey, recaptchaPrivateKey, true);
                                                String recaptchaChallenge = (String) parameterMap.get("recaptcha_challenge_field");
                                                String recaptchaResponse = (String) parameterMap.get("recaptcha_response_field");
                                                if (recaptchaResponse == null) {
                                                    valid = false;
                                                } else {
                                                    ReCaptchaResponse response = captcha.checkAnswer(remoteAddress, recaptchaChallenge, recaptchaResponse);
                                                    valid = response.isValid();
                                                }
                                            } else if (parameterMap.containsKey("g-recaptcha-response")) {
                                                // TODO: novo reCAPCHA.
                                                valid = false;
                                            } else {
                                                // reCAPCHA necessário.
                                                valid = false;
                                            }
                                        }
                                        if (valid) {
                                            String email = tokenizer.nextToken();
                                            User userLocal = User.get(email);
                                            Query queryLocal = userLocal == null ? null : userLocal.getQuery(date);
                                            if (queryLocal == null) {
                                                type = "HOLDN";
                                                code = 500;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Este ticket de liberação não existe mais.";
                                                } else {
                                                    message = "This release ticket does not exist any more.";
                                                }
                                                result = getMessageHMTL(title, message);
                                            } else if (queryLocal.isResult("WHITE")) {
                                                type = "HOLDN";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Esta mensagem já foi entregue.";
                                                } else {
                                                    message = "This message has already been delivered.";
                                                }
                                                result = getMessageHMTL(title, message);
                                            } else if (queryLocal.isWhiteSender()) {
                                                type = "HOLDN";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Esta mensagem já foi liberada.";
                                                } else {
                                                    message = "This message has already been released.";
                                                }
                                                result = getMessageHMTL(title, message);
                                            } else if (queryLocal.isBlockSender()) {
                                                type = "HOLDN";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Esta mensagem foi definitivamente bloqueada.";
                                                } else {
                                                    message = "This message has been permanently blocked.";
                                                }
                                                result = getMessageHMTL(title, message);
                                            } else if (queryLocal.isRecipientAdvised()) {
                                                type = "HOLDN";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "O destinatário ainda não decidiu pela liberação desta mensagem.";
                                                } else {
                                                    message = "The recipient has not yet decided to release this message.";
                                                }
                                                result = getMessageHMTL(title, message);
                                            } else if (queryLocal.adviseRecipientHOLD(date)) {
                                                type = "HOLDN";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Solicitação foi enviada com sucesso.";
                                                } else {
                                                    message = "Request was sent successfully.";
                                                }
                                                result = getMessageHMTL(title, message);
                                            } else {
                                                type = "HOLDN";
                                                code = 500;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "A solicitação não pode ser envada por falha de sistema.";
                                                } else {
                                                    message = "The request can not be committed due to system failure.";
                                                }
                                                result = getMessageHMTL(title, message);
                                            }
                                        } else {
                                            type = "HOLDN";
                                            code = 200;
                                            String message;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                message = "O desafio reCAPTCHA não foi "
                                                        + "resolvido. Tente novamente.";
                                            } else {
                                                message = "The reCAPTCHA challenge "
                                                        + "was not resolved. Try again.";
                                            }
                                            result = getHoldingHMTL(locale, message);
                                        }
                                    } catch (Exception ex) {
                                        type = "HOLDN";
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
                                        boolean valid = true;
                                        if (Core.hasRecaptchaKeys()) {
                                            HashMap<String,Object> parameterMap = getParameterMap(exchange);
                                            if (parameterMap.containsKey("recaptcha_challenge_field")
                                                    && parameterMap.containsKey("recaptcha_response_field")
                                                    ) {
                                                // reCAPCHA convencional.
                                                String recaptchaPublicKey = Core.getRecaptchaKeySite();
                                                String recaptchaPrivateKey = Core.getRecaptchaKeySecret();
                                                ReCaptcha captcha = ReCaptchaFactory.newReCaptcha(recaptchaPublicKey, recaptchaPrivateKey, true);
                                                String recaptchaChallenge = (String) parameterMap.get("recaptcha_challenge_field");
                                                String recaptchaResponse = (String) parameterMap.get("recaptcha_response_field");
                                                if (recaptchaResponse == null) {
                                                    valid = false;
                                                } else {
                                                    ReCaptchaResponse response = captcha.checkAnswer(remoteAddress, recaptchaChallenge, recaptchaResponse);
                                                    valid = response.isValid();
                                                }
                                            } else if (parameterMap.containsKey("g-recaptcha-response")) {
                                                // TODO: novo reCAPCHA.
                                                valid = false;
                                            } else {
                                                // reCAPCHA necessário.
                                                valid = false;
                                            }
                                        }
                                        if (valid) {
                                            String email = tokenizer.nextToken();
                                            User userLocal = User.get(email);
                                            Query queryLocal = userLocal == null ? null : userLocal.getQuery(date);
                                            if (queryLocal == null) {
                                                type = "UHOLD";
                                                code = 500;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Este ticket de liberação não existe mais.";
                                                } else {
                                                    message = "This release ticket does not exist any more.";
                                                }
                                                result = getMessageHMTL(title, message);
                                            } else if (!queryLocal.isHolding()) {
                                                type = "UHOLD";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Esta mensagem já foi entregue.";
                                                } else {
                                                    message = "This message has already been delivered.";
                                                }
                                                result = getMessageHMTL(title, message);
                                            } else if (queryLocal.isWhite()) {
                                                type = "UHOLD";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Esta mensagem já foi liberada e será entregue em breve.";
                                                } else {
                                                    message = "This message has already been released and will be delivered shortly.";
                                                }
                                                result = getMessageHMTL(title, message);
                                            } else if (queryLocal.whiteSender(date)) {
                                                type = "UHOLD";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "A mensagem foi liberada com sucesso e será entregue em breve.";
                                                } else {
                                                    message = "The message has been successfully released and will be delivered shortly.";
                                                }
                                                result = getMessageHMTL(title, message);
                                            } else {
                                                type = "UHOLD";
                                                code = 500;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "A liberação não pode ser efetivada por falha de sistema.";
                                                } else {
                                                    message = "The release can not be effected due to system failure.";
                                                }
                                                result = getMessageHMTL(title, message);
                                            }
                                        } else {
                                            type = "UHOLD";
                                            code = 200;
                                            String message;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                message = "O desafio reCAPTCHA não foi "
                                                        + "resolvido. Tente novamente.";
                                            } else {
                                                message = "The reCAPTCHA challenge "
                                                        + "was not resolved. Try again.";
                                            }
                                            result = getHoldingHMTL(locale, message);
                                        }
                                    } catch (Exception ex) {
                                        type = "UHOLD";
                                        code = 500;
                                        result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                                    }
                                } else if (operator.equals("block")) {
                                    String title;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        title = "Página de bloqueio do SPFBL";
                                    } else {
                                        title = "SPFBL block page";
                                    }
                                    try {
                                        boolean valid = true;
                                        if (Core.hasRecaptchaKeys()) {
                                            HashMap<String,Object> parameterMap = getParameterMap(exchange);
                                            if (parameterMap.containsKey("recaptcha_challenge_field")
                                                    && parameterMap.containsKey("recaptcha_response_field")
                                                    ) {
                                                // reCAPCHA convencional.
                                                String recaptchaPublicKey = Core.getRecaptchaKeySite();
                                                String recaptchaPrivateKey = Core.getRecaptchaKeySecret();
                                                ReCaptcha captcha = ReCaptchaFactory.newReCaptcha(recaptchaPublicKey, recaptchaPrivateKey, true);
                                                String recaptchaChallenge = (String) parameterMap.get("recaptcha_challenge_field");
                                                String recaptchaResponse = (String) parameterMap.get("recaptcha_response_field");
                                                if (recaptchaResponse == null) {
                                                    valid = false;
                                                } else {
                                                    ReCaptchaResponse response = captcha.checkAnswer(remoteAddress, recaptchaChallenge, recaptchaResponse);
                                                    valid = response.isValid();
                                                }
                                            } else if (parameterMap.containsKey("g-recaptcha-response")) {
                                                // TODO: novo reCAPCHA.
                                                valid = false;
                                            } else {
                                                // reCAPCHA necessário.
                                                valid = false;
                                            }
                                        }
                                        if (valid) {
                                            String email = tokenizer.nextToken();
                                            User userLocal = User.get(email);
                                            Query queryLocal = userLocal == null ? null : userLocal.getQuery(date);
                                            if (queryLocal == null) {
                                                type = "BLOCK";
                                                code = 500;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Este ticket de bloqueio não existe mais.";
                                                } else {
                                                    message = "This block ticket does not exist any more.";
                                                }
                                                result = getMessageHMTL(title, message);
                                            } else if (queryLocal.isResult("ACCEPT") && queryLocal.isWhiteSender()) {
                                                type = "BLOCK";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Esta remetente foi liberado por outro usuário.";
                                                } else {
                                                    message = "This sender has been released by another user.";
                                                }
                                                result = getMessageHMTL(title, message);
                                            } else if (queryLocal.isResult("ACCEPT") && queryLocal.isBlockSender()) {
                                                type = "BLOCK";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Esta remetente já foi bloqueado.";
                                                } else {
                                                    message = "This message has already been discarded.";
                                                }
                                                result = getMessageHMTL(title, message);
                                            } else if (queryLocal.isResult("ACCEPT") && queryLocal.blockSender(date)) {
                                                type = "BLOCK";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "O remetente foi bloqueado com sucesso.";
                                                } else {
                                                    message = "The sender was successfully blocked.";
                                                }
                                                result = getMessageHMTL(title, message);
                                            } else if (queryLocal.isResult("BLOCK") || queryLocal.isResult("REJECT")) {
                                                type = "BLOCK";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Esta mensagem já foi descartada.";
                                                } else {
                                                    message = "This message has already been discarded.";
                                                }
                                                result = getMessageHMTL(title, message);
                                            } else if (queryLocal.isWhiteSender()) {
                                                type = "BLOCK";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Esta mensagem foi liberada por outro usuário.";
                                                } else {
                                                    message = "This message has been released by another user.";
                                                }
                                                result = getMessageHMTL(title, message);
                                            } else if (queryLocal.isBlockSender() || queryLocal.isAnyLinkBLOCK()) {
                                                type = "BLOCK";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "Esta mensagem já foi bloqueada e será descartada em breve.";
                                                } else {
                                                    message = "This message has already been blocked and will be discarded soon.";
                                                }
                                                result = getMessageHMTL(title, message);
                                            } else if (queryLocal.blockSender(date)) {
                                                type = "BLOCK";
                                                code = 200;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "A mensagem foi bloqueada com sucesso e será descartada em breve.";
                                                } else {
                                                    message = "The message has been successfully blocked and will be discarded soon.";
                                                }
                                                result = getMessageHMTL(title, message);
                                            } else {
                                                type = "BLOCK";
                                                code = 500;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "O bloqueio não pode ser efetivado por falha de sistema.";
                                                } else {
                                                    message = "The block can not be effected due to system failure.";
                                                }
                                                result = getMessageHMTL(title, message);
                                            }
                                        } else {
                                            type = "BLOCK";
                                            code = 200;
                                            String message1;
                                            String message2;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                message1 = "A mensagem retida por suspeita de SPAM.";
                                                message2 = "O desafio reCAPTCHA não foi resolvido. Tente novamente.";
                                            } else {
                                                message1 = "The message retained on suspicion of SPAM.";
                                                message2 = "The reCAPTCHA challenge was not resolved. Try again.";
                                            }
                                            result = getBlockHMTL(locale, message1, message2);
                                        }
                                    } catch (Exception ex) {
                                        type = "BLOCK";
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
                                        
                                        boolean valid = true;
                                        if (Core.hasRecaptchaKeys()) {
                                            HashMap<String,Object> parameterMap = getParameterMap(exchange);
                                            if (parameterMap.containsKey("recaptcha_challenge_field")
                                                    && parameterMap.containsKey("recaptcha_response_field")
                                                    ) {
                                                // reCAPCHA convencional.
                                                String recaptchaPublicKey = Core.getRecaptchaKeySite();
                                                String recaptchaPrivateKey = Core.getRecaptchaKeySecret();
                                                ReCaptcha captcha = ReCaptchaFactory.newReCaptcha(recaptchaPublicKey, recaptchaPrivateKey, true);
                                                String recaptchaChallenge = (String) parameterMap.get("recaptcha_challenge_field");
                                                String recaptchaResponse = (String) parameterMap.get("recaptcha_response_field");
                                                if (recaptchaResponse == null) {
                                                    valid = false;
                                                } else {
                                                    ReCaptchaResponse response = captcha.checkAnswer(remoteAddress, recaptchaChallenge, recaptchaResponse);
                                                    valid = response.isValid();
                                                }
                                            } else if (parameterMap.containsKey("g-recaptcha-response")) {
                                                // TODO: novo reCAPCHA.
                                                valid = false;
                                            } else {
                                                // reCAPCHA necessário.
                                                valid = false;
                                            }
                                        }
                                        if (valid) {
                                            String id = tokenizer.nextToken();
                                            String message;
                                            if (Defer.release(id)) {
                                                String clientTicket = SPF.getClient(ticket);
                                                String sender = SPF.getSender(ticket);
                                                String recipient = SPF.getRecipient(ticket);
                                                if (clientTicket != null && sender != null && recipient != null) {
                                                    if (White.addExact(clientTicket + ":" + sender + ";PASS>" + recipient)) {
                                                        Server.logDebug("WHITE ADD " + clientTicket + ":" + sender + ";PASS>" + recipient);
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
                                            type = "DEFER";
                                            code = 200;
                                            result = getMessageHMTL(title, message);
                                        } else {
                                            type = "DEFER";
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
                                        type = "SPFSP";
                                        code = 500;
                                        result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                                    }
                                } else if (operator.equals("white")) {
                                    String title;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        title = "Página de desbloqueio do SPFBL";
                                    } else {
                                        title = "SPFBL unlock page";
                                    }
                                    try {
                                        boolean valid = true;
                                        if (Core.hasRecaptchaKeys()) {
                                            HashMap<String,Object> parameterMap = getParameterMap(exchange);
                                            if (parameterMap.containsKey("recaptcha_challenge_field")
                                                    && parameterMap.containsKey("recaptcha_response_field")
                                                    ) {
                                                // reCAPCHA convencional.
                                                String recaptchaPublicKey = Core.getRecaptchaKeySite();
                                                String recaptchaPrivateKey = Core.getRecaptchaKeySecret();
                                                ReCaptcha captcha = ReCaptchaFactory.newReCaptcha(recaptchaPublicKey, recaptchaPrivateKey, true);
                                                String recaptchaChallenge = (String) parameterMap.get("recaptcha_challenge_field");
                                                String recaptchaResponse = (String) parameterMap.get("recaptcha_response_field");
                                                if (recaptchaResponse == null) {
                                                    valid = false;
                                                } else {
                                                    ReCaptchaResponse response = captcha.checkAnswer(remoteAddress, recaptchaChallenge, recaptchaResponse);
                                                    valid = response.isValid();
                                                }
                                            } else if (parameterMap.containsKey("g-recaptcha-response")) {
                                                // TODO: novo reCAPCHA.
                                                valid = false;
                                            } else {
                                                // reCAPCHA necessário.
                                                valid = false;
                                            }
                                        }
                                        if (valid) {
                                            String white = White.normalizeTokenWhite(tokenizer.nextToken());
                                            String clientTicket = tokenizer.nextToken();
                                            white = clientTicket + white;
                                            client = Client.getByEmail(clientTicket.replace(":", ""));
                                            String ip = tokenizer.nextToken();
                                            String sender = tokenizer.nextToken();
                                            String recipient = tokenizer.nextToken();
                                            String hostname = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                                            String message;
                                            if (White.addExact(white)) {
                                                Block.clear(client, user, ip, sender, hostname, "PASS", recipient);
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "O desbloqueio do remetente '" + sender + "' foi efetuado com sucesso.";
                                                } else {
                                                    message = "The unblock of sender '" + sender + "' has been successfully performed.";
                                                }
                                                if (!enviarConfirmacaoDesbloqueio(recipient, sender, locale)) {
                                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                        message += "\nPor favor, informe ao remetente sobre o desbloqueio.";
                                                    } else {
                                                        message += "\nPlease inform the sender about the release.";
                                                    }
                                                }
                                            } else {
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "O desbloqueio do remetente '" + sender + "' já havia sido efetuado.";
                                                } else {
                                                    message = "The unblock of sender '" + sender + "' had been made.";
                                                }
                                            }
                                            type = "WHITE";
                                            code = 200;
                                            result = getMessageHMTL(title, message);
                                        } else {
                                            type = "WHITE";
                                            code = 200;
                                            String message;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                message = "O desafio reCAPTCHA não foi resolvido. "
                                                        + "Tente novamente.";
                                            } else {
                                                message = "The reCAPTCHA challenge was not resolved. "
                                                        + "Try again.";
                                            }
                                            result = getWhiteHMTL(locale, message);
                                        }
                                    } catch (Exception ex) {
                                        type = "SPFSP";
                                        code = 500;
                                        result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                                    }
                                } else {
                                    type = "HTTPC";
                                    code = 403;
                                    result = "Forbidden\n";
                                }
                            }
                        } catch (Exception ex) {
                            type = "HTTPC";
                            code = 403;
                            result = "Forbidden\n";
                        }
                    }
                } else if (request.equals("GET")) {
                    if (command.equals("/")) {
                        type = "MMENU";
                        code = 200;
                        String message;
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            message = "Este é página principal do serviço SPFBL.";
                        } else {
                            message = "This is SPFBL's main page.";
                        }
                        result = getMainHTML(locale, message, remoteAddress);
                    } else if (Domain.isEmail(command.substring(1))) {
                        String message;
                        String userEmail = command.substring(1).toLowerCase();
                        User userLogin = getUser(exchange);
                        if (userLogin != null && userLogin.isEmail(userEmail)) {
                            HashMap<String,Object> parameterMap = getParameterMap(exchange);
                            Long begin = (Long) parameterMap.get("begin");
                            message = getControlPanel(locale, userLogin, begin);
                        } else if ((userLogin = User.get(userEmail)) == null) {
                            message = getMessageHMTL(
                                    "Login do SPFBL",
                                    "Usuário inexistente."
                            );
                        } else if (userLogin.tooManyFails()) {
                            long failTime = userLogin.getFailTime();
                            int pageTime = (int) (failTime / 1000) + 1;
                            String tempoPunicao = getTempoPunicao(failTime);
                            message = getRedirectHMTL(
                                    "Login do SPFBL",
                                    "Conta temporariamente bloqueada por excesso de logins fracassados.\n"
                                    + "Aguarde cerca de " + tempoPunicao + " para tentar novamente.",
                                    command,
                                    pageTime
                            );
                        } else if (userLogin.hasTransitionOTP()) {
                            if (userLogin.hasSecretOTP()) {
                                message = getLoginOTPHMTL(
                                        locale,
                                        "Para confirmar a mudança de segredo TOTP,\n"
                                        + "digite o valor da nova chave enviada por e-mail:"
                                );
                            } else {
                                message = getLoginOTPHMTL(
                                        locale,
                                        "Para ativar a senha TOTP da sua conta,\n"
                                        + "digite o valor da chave enviada por e-mail:"
                                );
                            }
                        } else if (userLogin.hasSecretOTP()) {
                            message = getLoginOTPHMTL(
                                    locale,
                                    "Para entrar no painel de controle,\n"
                                    + "digite o valor da chave TOTP de sua conta:"
                            );
                        } else {
                            message = getSendOTPHMTL(
                                    locale,
                                    "Seu e-mail ainda não possui senha TOTP neste sistema.\n"
                                    + "Para receber a chave TOTP em seu e-mail,\n"
                                    + "resolva o reCAPTCHA abaixo."
                            );
                        }
                        type = "PANEL";
                        code = 200;
                        result = message;
                    } else if (Core.isLong(command.substring(1))) {
                        User userLogin = getUser(exchange);
                        if (userLogin == null) {
                            type = "QUERY";
                            code = 403;
                            result = "Forbidden\n";
                        } else {
                            long queryTime = Long.parseLong(command.substring(1));
                            User.Query query = userLogin.getQuery(queryTime);
                            if (query == null) {
                                type = "QUERY";
                                code = 403;
                                result = "Forbidden\n";
                            } else {
                                type = "QUERY";
                                code = 200;
                                result = getControlPanel(locale, query, queryTime);
                            }
                        }
                    } else if (command.startsWith("/dnsbl/")) {
                        String title;
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            title = "Página de checagem DNSBL";
                        } else {
                            title = "DNSBL check page";
                        }
                        int index = command.indexOf('/', 1) + 1;
                        String query = command.substring(index).trim();
                        if (Subnet.isValidIP(query)) {
                            type = "DNSBL";
                            code = 200;
                            String message;
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                message = "Resultado da checagem DNSBL do IP " + query + ".";
                            } else {
                                message = "DNSBL checking the result of IP " + query + ".";
                            }
                            result = getDNSBLHTML(locale, client, query, message);
                        } else if (Domain.isHostname(query)) {
                            type = "DNSBL";
                            code = 200;
                            String message;
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                message = "Resultado da checagem DNSBL do domínio '" + query + "'.";
                            } else {
                                message = "DNSBL checking the result of domain " + query + ".";
                            }
                            result = getDNSBLHTML(locale, client, query, message);
                        } else {
                            type = "DNSBL";
                            code = 500;
                            String message;
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                message = "O identificador informado não é um IP nem um domínio válido.";
                            } else {
                                message = "Informed identifier is not a valid IP or a valid domain.";
                            }
                            result = getMessageHMTL(title, message);
                        }
                    } else if (command.startsWith("/spam/")) {
                        try {
                            int index = command.indexOf('/', 1) + 1;
                            String ticket = command.substring(index);
                            ticket = URLDecoder.decode(ticket, "UTF-8");
                            String recipient = SPF.getRecipient(ticket);
                            boolean whiteBlockForm = recipient != null;
                            TreeSet<String> complainSet = SPF.addComplain(origin, ticket);
                            TreeSet<String> tokenSet = SPF.getTokenSet(ticket);
                            tokenSet = SPF.expandTokenSet(tokenSet);
                            TreeSet<String> selectionSet = new TreeSet<String>();
                            String message;
                            if (complainSet == null) {
                                complainSet = SPF.getComplain(ticket);
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    message = "A mensagem já havia sido denunciada antes.";
                                } else {
                                    message = "The message had been reported before.";
                                }
                            } else {
                                String clientTicket = SPF.getClient(ticket);
                                String sender = SPF.getSender(ticket);
                                if (clientTicket != null && sender != null && recipient != null) {
                                    if (White.dropExact(clientTicket + ":" + sender + ";PASS>" + recipient)) {
                                        Server.logDebug("WHITE DROP " + clientTicket + ":" + sender + ";PASS>" + recipient);
                                    }
                                }
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    message = "A mensagem foi denunciada com sucesso.";
                                } else {
                                    message = "The message has been reported as SPAM.";
                                }
                            }
                            for (String token : complainSet) {
                                if (!Subnet.isValidIP(token)) {
                                    selectionSet.add(token);
                                }
                            }
                            type = "SPFSP";
                            code = 200;
                            result = getComplainHMTL(locale, tokenSet, selectionSet, message, whiteBlockForm);
                        } catch (Exception ex) {
                            type = "SPFSP";
                            code = 500;
                            result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                        }
                    } else if (command.startsWith("/ham/")) {
                        try {
                            int index = command.indexOf('/', 1) + 1;
                            String ticket = command.substring(index);
                            ticket = URLDecoder.decode(ticket, "UTF-8");
                            TreeSet<String> tokenSet = SPF.deleteComplain(origin, ticket);
                            if (tokenSet == null) {
                                type = "SPFHM";
                                code = 404;
                                result = "ALREADY REMOVED\n";
                            } else {
                                type = "SPFHM";
                                code = 200;
                                String recipient = SPF.getRecipient(ticket);
                                result = "OK " + tokenSet + (recipient == null ? "" : " >" + recipient) + "\n";
                            }
                        } catch (Exception ex) {
                            type = "SPFHM";
                            code = 500;
                            result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                        }
                    } else if (command.startsWith("/release/")) {
                        String title;
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            title = "Página de liberação do SPFBL";
                        } else {
                            title = "SPFBL release page";
                        }
                        try {
                            int index = command.indexOf('/', 1) + 1;
                            String ticket = command.substring(index);
                            ticket = URLDecoder.decode(ticket, "UTF-8");
                            String registry = Server.decrypt(ticket);
                            index = registry.indexOf(' ');
                            Date date = Server.parseTicketDate(registry.substring(0, index));
                            if (System.currentTimeMillis() - date.getTime() > 432000000) {
                                // Ticket vencido com mais de 5 dias.
                                type = "DEFER";
                                code = 500;
                                String message;
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    message = "Este ticket de liberação está vencido.";
                                } else {
                                    message = "This release ticket is expired.";
                                }
                                result = getMessageHMTL(title, message);
                            } else {
                                String id = registry.substring(index + 1);
                                Defer defer = Defer.getDefer(date, id);
                                if (defer == null) {
                                    type = "DEFER";
                                    code = 500;
                                    String message;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        message = "Este ticket de liberação não existe ou já foi liberado antes.";
                                    } else {
                                        message = "This release ticket does not exist or has been released before.";
                                    }
                                    result = getMessageHMTL(title, message);
                                } else if (defer.isReleased()) {
                                    type = "DEFER";
                                    code = 200;
                                    String message;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        message = "Sua mensagem já havia sido liberada.";
                                    } else {
                                        message = "Your message had already been freed.";
                                    }
                                    result = getMessageHMTL(title, message);
                                } else {
                                    type = "DEFER";
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
                            }
                        } catch (Exception ex) {
                            type = "DEFER";
                            code = 500;
                            String message;
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                message = "Ocorreu um erro no processamento desta solicitação: "
                                        + ex.getMessage() == null ? "undefined error." : ex.getMessage();
                            } else {
                                message = "There was an error processing this request: "
                                        + ex.getMessage() == null ? "undefined error." : ex.getMessage();
                            }
                            result = getMessageHMTL(title, message);
                        }
                    } else if (command.startsWith("/unblock/")) {
                        String title;
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            title = "Página de desbloqueio do SPFBL";
                        } else {
                            title = "SPFBL unblock page";
                        }
                        try {
                            int index = command.indexOf('/', 1) + 1;
                            String ticket = command.substring(index);
                            ticket = URLDecoder.decode(ticket, "UTF-8");
                            String registry = Server.decrypt(ticket);
                            StringTokenizer tokenizer = new StringTokenizer(registry, " ");
                            Date date = Server.parseTicketDate(tokenizer.nextToken());
                            String clientTicket = tokenizer.nextToken();
                            String ip = tokenizer.nextToken();
                            if (!tokenizer.hasMoreTokens()) {
                                type = "BLOCK";
                                code = 200;
                                String message;
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    message = "Para desbloquear o IP '" + ip + "'\n"
                                            + "resolva o desafio reCAPTCHA abaixo.";
                                } else {
                                    message = "To unblock the IP '" + ip + "'\n"
                                            + "solve the CAPTCHA below.";
                                }
                                result = getUnblockDNSBLHMTL(locale, message);
                            } else {
                                String sender = tokenizer.nextToken();
                                String recipient = tokenizer.nextToken();
                                String hostname = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                                String mx = Domain.extractHost(sender, true);
                                SPF.Qualifier qualifier = SPF.getQualifier(ip, sender, hostname, true);
                                if (qualifier == SPF.Qualifier.PASS) {
                                    clientTicket = clientTicket == null ? "" : clientTicket + ':';
                                    String origem = Provider.containsExact(mx) ? sender : mx;
                                    if (System.currentTimeMillis() - date.getTime() > 432000000) {
                                        // Ticket vencido com mais de 5 dias.
                                        type = "BLOCK";
                                        code = 500;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Este ticket de desbloqueio está vencido.";
                                        } else {
                                            message = "This release ticket is expired.";
                                        }
                                        result = getMessageHMTL(title, message);
                                    } else if (sender == null || recipient == null) {
                                        type = "BLOCK";
                                        code = 500;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Este ticket de desbloqueio não "
                                                    + "contém remetente e destinatário.";
                                        } else {
                                            message = "This release ticket does not "
                                                    + "contains the sender and recipient.";
                                        }
                                        result = getMessageHMTL(title, message);
                                    } else if (White.containsExact(clientTicket + origem + ";PASS>" + recipient)) {
                                        type = "BLOCK";
                                        code = 200;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "O destinatário '" + recipient + "' "
                                                    + "já autorizou o recebimento de mensagens "
                                                    + "do remetente '" + sender + "'.";
                                        } else {
                                            message = "The recipient '" + recipient + "' "
                                                    + "already authorized receiving messages "
                                                    + "from sender '" + sender + "'.";
                                        }
                                        result = getMessageHMTL(title, message);
                                    } else if (Block.containsExact(clientTicket + origem + ";PASS>" + recipient)) {
                                        type = "BLOCK";
                                        code = 200;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "O destinatário '" + recipient + "' "
                                                    + "não decidiu se quer receber mensagens "
                                                    + "do remetente '" + sender + "'.\n"
                                                    + "Para que a reputação deste remetente "
                                                    + "não seja prejudicada neste sistema, "
                                                    + "é necessário que ele pare de tentar "
                                                    + "enviar mensagens para este "
                                                    + "destinatário até a sua decisão.\n"
                                                    + "Cada tentativa de envio por ele, "
                                                    + "conta um ponto negativo na "
                                                    + "reputação dele neste sistema.";
                                        } else {
                                            message = "The recipient '" + recipient + "' "
                                                    + "not decided whether to receive messages "
                                                    + "from sender '" + sender + "'.\n"
                                                    + "For the reputation of the sender "
                                                    + "is not impaired in this system, "
                                                    + "it needs to stop trying to "
                                                    + "send messages to this "
                                                    + "recipient until its decision.\n"
                                                    + "Each attempt to send him, "
                                                    + "has a negative point in "
                                                    + "reputation in this system.";
                                        }
                                        result = getMessageHMTL(title, message);
                                    } else {
                                        type = "BLOCK";
                                        code = 200;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Para solicitar o desbloqueio do remetente '" + sender + "'\n"
                                                    + "diretamente para o destinatário '" + recipient + "',\n"
                                                    + "resolva o desafio reCAPTCHA abaixo.";
                                        } else {
                                            message = "To request unblock the sender '" + sender + "'\n"
                                                    + "directly to the recipient '" + recipient + "',\n"
                                                    + "solve the challenge reCAPTCHA below.";
                                        }
                                        result = getUnblockHMTL(locale, message);
                                    }
                                } else {
                                    type = "BLOCK";
                                    code = 500;
                                    String message;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        message = "O IP " + ip + " não foi definido no registro SPF do domínio '" + mx + "'.\n"
                                                + "Para que seja possível solicitar o desbloqueio ao destinário, por meio deste sistema,\n"
                                                + "configure o SPF deste domínio de modo que o envio por meio do mesmo IP resulte em PASS.\n"
                                                + "Após fazer esta modificação, aguarde algumas horas pela propagação DNS,\n"
                                                + "e volte a acessar esta mesma página para prosseguir com o processo de desbloqueio.";
                                    } else {
                                        message = "The IP " + ip + " was not defined in the domain '" + mx + "' SPF record.\n"
                                                + "To be able to request unblocking to recipient, through this system,\n"
                                                + "set the SPF record of this domain so that sending through the same IP results in PASS.\n"
                                                + "After making this change, wait a few hours for DNS propagation,\n"
                                                + "and re-access the same page to proceed with the unblock process.";
                                    }
                                    result = getMessageHMTL(title, message);
                                }
                            }
                        } catch (Exception ex) {
                            Server.logError(ex);
                            type = "BLOCK";
                            code = 500;
                            String message;
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                message = "Ocorreu um erro no processamento desta solicitação: "
                                        + ex.getMessage() == null ? "undefined error." : ex.getMessage();
                            } else {
                                message = "There was an error processing this request: "
                                        + ex.getMessage() == null ? "undefined error." : ex.getMessage();
                            }
                            result = getMessageHMTL(title, message);
                        }
                    } else if (command.startsWith("/white/")) {
                        String title;
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            title = "Página de desbloqueio do SPFBL";
                        } else {
                            title = "SPFBL unblock page";
                        }
                        try {
                            int index = command.indexOf('/', 1) + 1;
                            String ticket = command.substring(index);
                            ticket = URLDecoder.decode(ticket, "UTF-8");
                            String registry = Server.decrypt(ticket);
                            StringTokenizer tokenizer = new StringTokenizer(registry, " ");
                            Date date = Server.parseTicketDate(tokenizer.nextToken());
                            String white = tokenizer.nextToken();
                            String clientTicket = tokenizer.nextToken();
                            String ip = tokenizer.nextToken();
                            String sender = tokenizer.nextToken();
                            String recipient = tokenizer.nextToken();
                            String hostname = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                            if (System.currentTimeMillis() - date.getTime() > 432000000) {
                                // Ticket vencido com mais de 5 dias.
                                type = "WHITE";
                                code = 500;
                                String message;
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    message =  "Este ticket de desbloqueio está vencido.";
                                } else {
                                    message =  "This unblock ticket is expired.";
                                }
                                result = getMessageHMTL(title, message);
                            } else if (White.containsExact(white)) {
                                type = "WHITE";
                                code = 200;
                                String message;
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    message = "Já houve liberação deste remetente '"
                                            + "" + sender + "' pelo destinatário '"
                                            + "" + recipient + "'.";
                                } else {
                                    message = "There have been release from this sender '"
                                            + "" + sender + "' by recipient '"
                                            + "" + recipient + "'.";
                                }
                                result = getMessageHMTL(title, message);
                            } else {
                                type = "WHITE";
                                code = 200;
                                String message;
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    message = "Para desbloquear este remetente '" + sender + "',\n"
                                            + "resolva o desafio reCAPTCHA abaixo.";
                                } else {
                                    message = "To unblock this sender '" + sender + "',\n"
                                            + "please solve the reCAPTCHA below.";
                                }
                                result = getWhiteHMTL(locale, message);
                            }
                        } catch (Exception ex) {
                            type = "WHITE";
                            code = 500;
                            String message;
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                message = "Ocorreu um erro no processamento desta solicitação: "
                                        + ex.getMessage() == null ? "undefined error." : ex.getMessage();
                            } else {
                                message = "There was an error processing this request: "
                                        + ex.getMessage() == null ? "undefined error." : ex.getMessage();
                            }
                            result = getMessageHMTL(title, message);
                        }
                    } else if (command.startsWith("/favicon.ico")) {
                        type = "HTTPC";
                        code = 403;
                        result = "Forbidden\n";
                    } else {
                        try {
                            String ticket = command.substring(1);
                            byte[] byteArray = Server.decryptToByteArrayURLSafe(ticket);
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
                                String title;
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    title = "Página do SPFBL";
                                } else {
                                    title = "SPFBL page";
                                }
                                type = "HTTPC";
                                code = 500;
                                String message;
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    message = "Ticket expirado.";
                                } else {
                                    message = "Expired ticket.";
                                }
                                result = getMessageHMTL(title, message);
                            } else {
                                String query = Core.HUFFMAN.decode(byteArray, 8);
                                StringTokenizer tokenizer = new StringTokenizer(query, " ");
                                String operator = tokenizer.nextToken();
                                if (operator.equals("spam")) {
                                    try {
                                        String sender = null;
                                        String recipient = null;
                                        String clientTicket = null;
                                        TreeSet<String> tokenSet = new TreeSet<String>();
                                        while (tokenizer.hasMoreTokens()) {
                                            String token = tokenizer.nextToken();
                                            if (token.startsWith(">") && Domain.isEmail(token.substring(1))) {
                                                recipient = token.substring(1);
                                            } else if (token.endsWith(":") && Domain.isEmail(token.substring(0, token.length() - 1))) {
                                                clientTicket = token.substring(0, token.length() - 1);
                                            } else if (token.startsWith("@") && Domain.isHostname(token.substring(1))) {
                                                sender = token;
                                                tokenSet.add(token);
                                            } else if (Domain.isEmail(token)) {
                                                sender = token;
                                                tokenSet.add(token);
                                            } else {
                                                tokenSet.add(token);
                                            }
                                        }
                                        boolean whiteBlockForm = recipient != null;
                                        TreeSet<String> complainSet = SPF.addComplain(origin, date, tokenSet, recipient);
                                        tokenSet = SPF.expandTokenSet(tokenSet);
                                        TreeSet<String> selectionSet = new TreeSet<String>();
                                        String message;
                                        if (complainSet == null) {
                                            complainSet = SPF.getComplain(ticket);
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                message = "A mensagem já havia sido denunciada antes.";
                                            } else {
                                                message = "The message had been reported before.";
                                            }
                                        } else {
                                            if (clientTicket != null && sender != null && recipient != null) {
                                                if (White.dropExact(clientTicket + ":" + sender + ";PASS>" + recipient)) {
                                                    Server.logDebug("WHITE DROP " + clientTicket + ":" + sender + ";PASS>" + recipient);
                                                }
                                            }
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                message = "A mensagem foi denunciada com sucesso.";
                                            } else {
                                                message = "The message has been reported as SPAM.";
                                            }
                                        }
                                        for (String token : complainSet) {
                                            if (!Subnet.isValidIP(token)) {
                                                selectionSet.add(token);
                                            }
                                        }
                                        type = "SPFSP";
                                        code = 200;
                                        result = getComplainHMTL(locale, tokenSet, selectionSet, message, whiteBlockForm);
                                    } catch (Exception ex) {
                                        type = "SPFSP";
                                        code = 500;
                                        result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                                    }
                                } else if (operator.equals("unblock")) {
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
                                            type = "BLOCK";
                                            code = 200;
                                            String message;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                message = "Para desbloquear o IP '" + ip + "'\n"
                                                        + "resolva o desafio reCAPTCHA abaixo.";
                                            } else {
                                                message = "To unblock the IP '" + ip + "'\n"
                                                        + "solve the CAPTCHA below.";
                                            }
                                            result = getUnblockDNSBLHMTL(locale, message);
                                        } else {
                                            String sender = tokenizer.nextToken();
                                            String recipient = tokenizer.nextToken();
                                            String hostname = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                                            String mx = Domain.extractHost(sender, true);
                                            SPF.Qualifier qualifier = SPF.getQualifier(ip, sender, hostname, true);
                                            if (qualifier == SPF.Qualifier.PASS) {
                                                clientTicket = clientTicket == null ? "" : clientTicket + ':';
                                                String origem = Provider.containsExact(mx) ? sender : mx;
                                                if (sender == null || recipient == null) {
                                                    type = "BLOCK";
                                                    code = 500;
                                                    String message;
                                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                        message = "Este ticket de desbloqueio não "
                                                                + "contém remetente e destinatário.";
                                                    } else {
                                                        message = "This release ticket does not "
                                                                + "contains the sender and recipient.";
                                                    }
                                                    result = getMessageHMTL(title, message);
                                                } else if (White.containsExact(clientTicket + origem + ";PASS>" + recipient)) {
                                                    type = "BLOCK";
                                                    code = 200;
                                                    String message;
                                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                        message = "O destinatário '" + recipient + "' "
                                                                + "já autorizou o recebimento de mensagens "
                                                                + "do remetente '" + sender + "'.";
                                                    } else {
                                                        message = "The recipient '" + recipient + "' "
                                                                + "already authorized receiving messages "
                                                                + "from sender '" + sender + "'.";
                                                    }
                                                    result = getMessageHMTL(title, message);
                                                } else if (Block.containsExact(clientTicket + origem + ";PASS>" + recipient)) {
                                                    type = "BLOCK";
                                                    code = 200;
                                                    String message;
                                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                        message =  "O destinatário '" + recipient + "' "
                                                                + "não decidiu se quer receber mensagens "
                                                                + "do remetente '" + sender + "'.\n"
                                                                + "Para que a reputação deste remetente "
                                                                + "não seja prejudicada neste sistema, "
                                                                + "é necessário que ele pare de tentar "
                                                                + "enviar mensagens para este "
                                                                + "destinatário até a sua decisão.\n"
                                                                + "Cada tentativa de envio por ele, "
                                                                + "conta um ponto negativo na "
                                                                + "reputação dele neste sistema.";
                                                    } else {
                                                        message =  "The recipient '" + recipient + "' "
                                                                + "not decided whether to receive messages "
                                                                + "from sender '" + sender + "'.\n"
                                                                + "For the reputation of the sender "
                                                                + "is not impaired in this system, "
                                                                + "it needs to stop trying to "
                                                                + "send messages to this "
                                                                + "recipient until its decision.\n"
                                                                + "Each attempt to send him, "
                                                                + "has a negative point in "
                                                                + "reputation in this system.";
                                                    }
                                                    result = getMessageHMTL(title, message);
                                                } else {
                                                    type = "BLOCK";
                                                    code = 200;
                                                    String message;
                                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                        message = "Para solicitar o desbloqueio do remetente '" + sender + "'\n"
                                                                + "diretamente para o destinatário '" + recipient + "',\n"
                                                                + "resolva o desafio reCAPTCHA abaixo.";
                                                    } else {
                                                        message = "To request unblock the sender '" + sender + "'\n"
                                                                + "directly to the recipient '" + recipient + "',\n"
                                                                + "solve the challenge reCAPTCHA below.";
                                                    }
                                                    result = getUnblockHMTL(locale, message);
                                                }
                                            } else {
                                                type = "BLOCK";
                                                code = 500;
                                                String message;
                                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                    message = "O IP " + ip + " não foi definido no registro SPF do domínio '" + mx + "'.\n"
                                                            + "Para que seja possível solicitar o desbloqueio ao destinário, por meio deste sistema,\n"
                                                            + "configure o SPF deste domínio de modo que o envio por meio do mesmo IP resulte em PASS.\n"
                                                            + "Após fazer esta modificação, aguarde algumas horas pela propagação DNS,\n"
                                                            + "e volte a acessar esta mesma página para prosseguir com o processo de desbloqueio.";
                                                } else {
                                                    message = "The IP " + ip + " was not defined in the domain '" + mx + "' SPF record.\n"
                                                            + "To be able to request unblocking to recipient, through this system,\n"
                                                            + "set the SPF record of this domain so that sending through the same IP results in PASS.\n"
                                                            + "After making this change, wait a few hours for DNS propagation,\n"
                                                            + "and re-access the same page to proceed with the unblock process.";
                                                }
                                                result = getMessageHMTL(title, message);
                                            }
                                        }
                                    } catch (Exception ex) {
                                        Server.logError(ex);
                                        type = "BLOCK";
                                        code = 500;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Ocorreu um erro no processamento desta solicitação: "
                                                    + ex.getMessage() == null ? "undefined error." : ex.getMessage();
                                        } else {
                                            message = "There was an error processing this request: "
                                                    + ex.getMessage() == null ? "undefined error." : ex.getMessage();
                                        }
                                        result = getMessageHMTL(title, message);
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
                                    Query queryLocal = userLocal == null ? null : userLocal.getQuery(date);
                                    if (queryLocal == null) {
                                        type = "HOLDN";
                                        code = 500;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Este ticket de liberação não existe mais.";
                                        } else {
                                            message = "This release ticket does not exist any more.";
                                        }
                                        result = getMessageHMTL(title, message);
                                    } else if (queryLocal.isResult("WHITE")) {
                                        type = "HOLDN";
                                        code = 200;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Esta mensagem já foi entregue.";
                                        } else {
                                            message = "This message has already been delivered.";
                                        }
                                        result = getMessageHMTL(title, message);
                                    } else if (queryLocal.isWhiteSender()) {
                                        type = "HOLDN";
                                        code = 200;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Esta mensagem já foi liberada.";
                                        } else {
                                            message = "This message has already been released.";
                                        }
                                        result = getMessageHMTL(title, message);
                                    } else if (queryLocal.isBlockSender()) {
                                        type = "HOLDN";
                                        code = 200;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Esta mensagem foi definitivamente bloqueada.";
                                        } else {
                                            message = "This message has been permanently blocked.";
                                        }
                                        result = getMessageHMTL(title, message);
                                    } else if (queryLocal.isRecipientAdvised()) {
                                        type = "HOLDN";
                                        code = 200;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "O destinatário ainda não decidiu pela liberação desta mensagem.";
                                        } else {
                                            message = "The recipient has not yet decided to release this message.";
                                        }
                                        result = getMessageHMTL(title, message);
                                    } else {
                                        type = "HOLDN";
                                        code = 200;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Para solicitar liberação desta mensagem, "
                                                    + "resolva o CAPTCHA abaixo.";
                                        } else {
                                            message = "To request release of this message, "
                                                + "solve the CAPTCHA below.";
                                        }
                                        result = getHoldingHMTL(locale, message);
                                    }
                                } else if (operator.equals("unhold")) {
                                    String title;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        title = "Página de liberação do SPFBL";
                                    } else {
                                        title = "SPFBL release page";
                                    }
                                    String email = tokenizer.nextToken();
                                    User userLocal = User.get(email);
                                    DateFormat dateFormat = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM, locale);
                                    GregorianCalendar calendar = new GregorianCalendar();
                                    calendar.setTimeInMillis(date);
                                    Server.logTrace(dateFormat.format(calendar.getTime()));
                                    Query queryLocal = userLocal == null ? null : userLocal.getQuery(date);
                                    if (queryLocal == null) {
                                        type = "UHOLD";
                                        code = 500;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Este ticket de liberação não existe mais.";
                                        } else {
                                            message = "This release ticket does not exist any more.";
                                        }
                                        result = getMessageHMTL(title, message);
                                    } else if (!queryLocal.isHolding()) {
                                        type = "UHOLD";
                                        code = 200;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Esta mensagem já foi entregue.";
                                        } else {
                                            message = "This message has already been delivered.";
                                        }
                                        result = getMessageHMTL(title, message);
                                    } else if (queryLocal.isWhite()) {
                                        type = "UHOLD";
                                        code = 200;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Esta mensagem já foi liberada e será entregue em breve.";
                                        } else {
                                            message = "This message has already been released and will be delivered shortly.";
                                        }
                                        result = getMessageHMTL(title, message);
                                    } else {
                                        type = "UHOLD";
                                        code = 200;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Para confirmar a liberação desta mensagem, "
                                                    + "resolva o CAPTCHA abaixo.";
                                        } else {
                                            message = "To confirm the release of this message, "
                                                + "solve the CAPTCHA below.";
                                        }
                                        result = getHoldingHMTL(locale, message);
                                    }
                                } else if (operator.equals("block")) {
                                    String title;
                                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                                        title = "Página de bloqueio do SPFBL";
                                    } else {
                                        title = "SPFBL block page";
                                    }
                                    String email = tokenizer.nextToken();
                                    User userLocal = User.get(email);
                                    DateFormat dateFormat = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM, locale);
                                    GregorianCalendar calendar = new GregorianCalendar();
                                    calendar.setTimeInMillis(date);
                                    Server.logTrace(dateFormat.format(calendar.getTime()));
                                    Query queryLocal = userLocal == null ? null : userLocal.getQuery(date);
                                    if (queryLocal == null) {
                                        type = "BLOCK";
                                        code = 500;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Este ticket de liberação não existe mais.";
                                        } else {
                                            message = "This release ticket does not exist any more.";
                                        }
                                        result = getMessageHMTL(title, message);
                                    } else if (queryLocal.isResult("ACCEPT") && queryLocal.isWhiteSender()) {
                                        type = "BLOCK";
                                        code = 200;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Esta remetente foi liberado por outro usuário.";
                                        } else {
                                            message = "This sender has been released by another user.";
                                        }
                                        result = getMessageHMTL(title, message);
                                    } else if (queryLocal.isResult("ACCEPT") && queryLocal.isBlockSender()) {
                                        type = "BLOCK";
                                        code = 200;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Esta remetente já foi bloqueado.";
                                        } else {
                                            message = "This message has already been discarded.";
                                        }
                                        result = getMessageHMTL(title, message);
                                    } else if (queryLocal.isResult("ACCEPT")) {
                                        type = "BLOCK";
                                        code = 200;
                                        String message1;
                                        String message2;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message1 = "Mensagem com forte suspeita de SPAM.";
                                            message2 = "Para confirmar o bloqueio deste remetente, resolva o CAPTCHA abaixo.";
                                        } else {
                                            message1 = "Message with strong suspicion of SPAM.";
                                            message2 = "To confirm the block of this sender, solve the CAPTCHA below.";
                                        }
                                        result = getBlockHMTL(locale, message1, message2);
                                    } else if (queryLocal.isResult("BLOCK") || queryLocal.isResult("REJECT")) {
                                        type = "BLOCK";
                                        code = 200;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Esta mensagem já foi descartada.";
                                        } else {
                                            message = "This message has already been discarded.";
                                        }
                                        result = getMessageHMTL(title, message);
                                    } else if (queryLocal.isWhiteSender()) {
                                        type = "BLOCK";
                                        code = 200;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Esta mensagem foi liberada por outro usuário.";
                                        } else {
                                            message = "This message has been released by another user.";
                                        }
                                        result = getMessageHMTL(title, message);
                                    } else if (queryLocal.isBlockSender() || queryLocal.isAnyLinkBLOCK()) {
                                        type = "BLOCK";
                                        code = 200;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Esta mensagem já foi bloqueada e será descartada em breve.";
                                        } else {
                                            message = "This message has already been blocked and will be discarded soon.";
                                        }
                                        result = getMessageHMTL(title, message);
                                    } else {
                                        type = "BLOCK";
                                        code = 200;
                                        String message1;
                                        String message2;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message1 = "A mensagem foi retida por suspeita de SPAM.";
                                            message2 = "Para confirmar o bloqueio deste remetente, resolva o CAPTCHA abaixo.";
                                        } else {
                                            message1 = "The message was retained on suspicion of SPAM.";
                                            message2 = "To confirm the block of this sender, solve the CAPTCHA below.";
                                        }
                                        result = getBlockHMTL(locale, message1, message2);
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
                                            type = "DEFER";
                                            code = 500;
                                            String message;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                message = "Este ticket de liberação não existe ou já foi liberado antes.";
                                            } else {
                                                message = "This release ticket does not exist or has been released before.";
                                            }
                                            result = getMessageHMTL(title, message);
                                        } else if (defer.isReleased()) {
                                            type = "DEFER";
                                            code = 200;
                                            String message;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                message = "Sua mensagem já havia sido liberada.";
                                            } else {
                                                message = "Your message had already been freed.";
                                            }
                                            result = getMessageHMTL(title, message);
                                        } else {
                                            type = "DEFER";
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
                                        type = "DEFER";
                                        code = 500;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Ocorreu um erro no processamento desta solicitação: "
                                                    + ex.getMessage() == null ? "undefined error." : ex.getMessage();
                                        } else {
                                            message = "There was an error processing this request: "
                                                    + ex.getMessage() == null ? "undefined error." : ex.getMessage();
                                        }
                                        result = getMessageHMTL(title, message);
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
                                        if (White.containsExact(white)) {
                                            type = "WHITE";
                                            code = 200;
                                            String message;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                message = "Já houve liberação deste remetente '"
                                                        + "" + sender + "' pelo destinatário '"
                                                        + "" + recipient + "'.";
                                            } else {
                                                message = "There have been release from this sender '"
                                                        + "" + sender + "' by recipient '"
                                                        + "" + recipient + "'.";
                                            }
                                            result = getMessageHMTL(title, message);
                                        } else {
                                            type = "WHITE";
                                            code = 200;
                                            String message;
                                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                                message = "Para desbloquear este remetente '" + sender + "',\n"
                                                        + "resolva o desafio reCAPTCHA abaixo.";
                                            } else {
                                                message = "To unblock this sender '" + sender + "',\n"
                                                        + "please solve the reCAPTCHA below.";
                                            }
                                            result = getWhiteHMTL(locale, message);
                                        }
                                    } catch (Exception ex) {
                                        type = "WHITE";
                                        code = 500;
                                        String message;
                                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                                            message = "Ocorreu um erro no processamento desta solicitação: "
                                                    + ex.getMessage() == null ? "undefined error." : ex.getMessage();
                                        } else {
                                            message = "There was an error processing this request: "
                                                    + ex.getMessage() == null ? "undefined error." : ex.getMessage();
                                        }
                                        result = getMessageHMTL(title, message);
                                    }
                                } else {
                                    type = "HTTPC";
                                    code = 403;
                                    result = "Forbidden\n";
                                }
                            }
                        } catch (Exception ex) {
                            type = "HTTPC";
                            code = 403;
                            result = "Forbidden\n";
                        }
                    }
                } else if (request.equals("PUT")) {
                    if (command.startsWith("/spam/")) {
                        try {
                            int index = command.indexOf('/', 1) + 1;
                            String ticket = command.substring(index);
                            ticket = URLDecoder.decode(ticket, "UTF-8");
                            TreeSet<String> complainSet = SPF.addComplain(origin, ticket);
                            if (complainSet == null) {
                                type = "SPFSP";
                                code = 404;
                                result = "DUPLICATE COMPLAIN\n";
                            } else {
                                type = "SPFSP";
                                code = 200;
                                String recipient = SPF.getRecipient(ticket);
                                result = "OK " + complainSet + (recipient == null ? "" : " >" + recipient) + "\n";
                            }
                        } catch (Exception ex) {
                            type = "SPFSP";
                            code = 500;
                            result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                        }
                    } else if (command.startsWith("/ham/")) {
                        try {
                            int index = command.indexOf('/', 1) + 1;
                            String ticket = command.substring(index);
                            ticket = URLDecoder.decode(ticket, "UTF-8");
                            TreeSet<String> tokenSet = SPF.deleteComplain(origin, ticket);
                            if (tokenSet == null) {
                                type = "SPFHM";
                                code = 404;
                                result = "ALREADY REMOVED\n";
                            } else {
                                type = "SPFHM";
                                code = 200;
                                String recipient = SPF.getRecipient(ticket);
                                result = "OK " + tokenSet + (recipient == null ? "" : " >" + recipient) + "\n";
                            }
                        } catch (Exception ex) {
                            type = "SPFHM";
                            code = 500;
                            result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                        }
                    } else {
                        try {
                            String ticket = command.substring(1);
                            byte[] byteArray = Server.decryptToByteArrayURLSafe(ticket);
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
                                type = "HTTPC";
                                code = 500;
                                result = "EXPIRED TICKET.\n";
                            } else {
                                String query = Core.HUFFMAN.decode(byteArray, 8);
                                StringTokenizer tokenizer = new StringTokenizer(query, " ");
                                command = tokenizer.nextToken();
                                if (command.equals("spam")) {
                                    try {
                                        type = "SPFSP";
                                        code = 200;
                                        String sender = null;
                                        String recipient = null;
                                        String clientTicket = null;
                                        TreeSet<String> tokenSet = new TreeSet<String>();
                                        while (tokenizer.hasMoreTokens()) {
                                            String token = tokenizer.nextToken();
                                            if (token.startsWith(">") && Domain.isEmail(token.substring(1))) {
                                                recipient = token.substring(1);
                                            } else if (token.endsWith(":") && Domain.isEmail(token.substring(0, token.length() - 1))) {
                                                clientTicket = token.substring(0, token.length() - 1);
                                            } else if (token.startsWith("@") && Domain.isHostname(token.substring(1))) {
                                                sender = token;
                                                tokenSet.add(token);
                                            } else if (Domain.isEmail(token)) {
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
                                                    Server.logDebug("WHITE DROP " + clientTicket + ":" + sender + ";PASS>" + recipient);
                                                }
                                            }
                                            result = "OK " + complainSet + (recipient == null ? "" : " >" + recipient) + "\n";
                                        }
                                    } catch (Exception ex) {
                                        type = "SPFSP";
                                        code = 500;
                                        result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                                    }
                                } else {
                                    type = "HTTPC";
                                    code = 403;
                                    result = "Forbidden\n";
                                }
                            }
                        } catch (Exception ex) {
                            type = "HTTPC";
                            code = 403;
                            result = "Forbidden\n";
                        }
                    }
                } else {
                    type = "HTTPC";
                    code = 405;
                    result = "Method not allowed.\n";
                }
                try {
                    response(code, result, exchange);
                    command = request + " " + command;
                    result = code + " " + result;
                } catch (IOException ex) {
                    result = ex.getMessage();
                }
                Server.logQuery(
                        time, type,
                        origin,
                        command,
                        result
                        );
            } catch (Exception ex) {
                Server.logError(ex);
            } finally {
                exchange.close();
            }
        }
    }
    
    private static boolean enviarDesbloqueioDNSBL(
            Locale locale,
            String url,
            String ip,
            String email
            ) {
        if (
                Core.hasSMTP()
                && Core.hasAdminEmail()
                && Domain.isEmail(email)
                && url != null
                && !NoReply.contains(email, true)
                ) {
            try {
                Server.logDebug("sending unblock by e-mail.");
                if (email.endsWith(".br")) {
                    locale = new Locale("pt", "BR");
                } else if (email.endsWith(".pt")) {
                    locale = new Locale("pt", "PT");
                }
                User user = User.get(email);
                InternetAddress[] recipients;
                if (user == null) {
                    recipients = InternetAddress.parse(email);
                } else {
                    recipients = new InternetAddress[1];
                    recipients[0] = user.getInternetAddress();
                }
                Properties props = System.getProperties();
                Session session = Session.getDefaultInstance(props);
                MimeMessage message = new MimeMessage(session);
                message.setHeader("Date", Core.getEmailDate());
                message.setFrom(Core.getAdminInternetAddress());
                message.addRecipients(Message.RecipientType.TO, recipients);
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    message.setSubject("Chave de desbloqueio SPFBL");
                } else {
                    message.setSubject("Unblocking key SPFBL");
                }
                // Corpo da mensagem.
                StringBuilder builder = new StringBuilder();
                builder.append("<html>\n");
                builder.append("  <head>\n");
                builder.append("    <meta charset=\"UTF-8\">\n");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("    <title>Chave de desbloqueio SPFBL</title>\n");
                } else {
                    builder.append("    <title>Unblocking key SPFBL</title>\n");
                }
                builder.append("  </head>\n");
                builder.append("  <body>\n");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("       Foi solicitado o desbloqueio do IP ");
                    builder.append(ip);
                    builder.append(" da listagem DNSBL do nosso sistema.<br>\n");
                    builder.append("       Se você é o administrador deste IP e fez esta solicitação,<br>\n");
                    builder.append("       acesse esta URL e resolva o reCAPTCHA para finalizar o procedimento:<br>\n");
                } else {
                    builder.append("       You asked to unblock the IP ");
                    builder.append(ip);
                    builder.append(" from our DNSBL.<br>\n");
                    builder.append("       If you are the administrator of this IP and made this request,<br>\n");
                    builder.append("       go to this URL and solve the reCAPTCHA to finish the procedure:<br>\n");
                }
                builder.append("       <a href=\"");
                builder.append(url);
                builder.append("\">");
                builder.append(url);
                builder.append("</a><br>\n");
                builder.append("    <br>\n");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("    <small>Powered by <a target=\"_blank\" href=\"http://spfbl.net/dnsbl/\">SPFBL.net</a></small><br>\n");
                } else {
                    builder.append("    <small>Powered by <a target=\"_blank\" href=\"http://spfbl.net/dnsbl/english/\">SPFBL.net</a></small><br>\n");
                }
                builder.append("  </body>\n");
                builder.append("</html>\n");
                message.setContent(builder.toString(), "text/html;charset=UTF-8");
                message.saveChanges();
                // Enviar mensagem.
                return Core.sendMessage(message);
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        } else {
            return false;
        }
    }
    
    private static boolean enviarOTP(
            Locale locale,
            User user
            ) {
        if (!Core.hasSMTP()) {
            Server.logError("no SMTP account to send TOTP.");
            return false;
        } else if (!Core.hasAdminEmail()) {
            Server.logError("no admin e-mail to send TOTP.");
            return false;
        } else if (user == null) {
            Server.logError("no user definied to send TOTP.");
            return false;
        } else if (NoReply.contains(user.getEmail(), true)) {
            Server.logError("cannot send TOTP because user is registered in noreply.");
            return false;
        } else {
            try {
                Server.logDebug("sending TOTP by e-mail.");
                if (user.getEmail().endsWith(".br")) {
                    locale = new Locale("pt", "BR");
                } else if (user.getEmail().endsWith(".pt")) {
                    locale = new Locale("pt", "PT");
                }
                InternetAddress[] recipients = new InternetAddress[1];
                recipients[0] = user.getInternetAddress();
                Properties props = System.getProperties();
                Session session = Session.getDefaultInstance(props);
                MimeMessage message = new MimeMessage(session);
                message.setHeader("Date", Core.getEmailDate());
                message.setFrom(Core.getAdminInternetAddress());
                message.addRecipients(Message.RecipientType.TO, recipients);
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    message.setSubject("Chave TOTP do SPFBL");
                } else {
                    message.setSubject("SPFBL TOTP key");
                }
                // Corpo da mensagem.
                StringBuilder builder = new StringBuilder();
                builder.append("<html>\n");
                builder.append("  <head>\n");
                builder.append("    <meta charset=\"UTF-8\">\n");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("    <title>Chave TOTP do SPFBL</title>\n");
                } else {
                    builder.append("    <title>SPFBL TOTP key</title>\n");
                }
                builder.append("  </head>\n");
                builder.append("  <body>\n");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("       Sua chave TOTP no sistema SPFBL em ");
                    builder.append(Core.getHostname());
                    builder.append(":<br>\n");
                    builder.append("       <img src=\"cid:qrcode\"><br>\n");
                    builder.append("       Carregue o QRCode acima em seu Google Authenticator<br>\n");
                    builder.append("       ou em outro aplicativo TOTP de sua peferência.<br>\n");
                } else {
                    builder.append("       Your TOTP key in SPFBL system at ");
                    builder.append(Core.getHostname());
                    builder.append(":<br>\n");
                    builder.append("       <img src=\"cid:qrcode\">\n");
                    builder.append("       Load QRCode above on your Google Authenticator<br>\n");
                    builder.append("       or on other application TOTP of your choice.<br>\n");
                }
                builder.append("  </body>\n");
                builder.append("</html>\n");
                // Making HTML part.
                MimeBodyPart htmlPart = new MimeBodyPart();
                htmlPart.setContent(builder.toString(), "text/html;charset=UTF-8");
                // Making image part.
                MimeBodyPart imagePart = new MimeBodyPart();
                String code = "otpauth://totp/" + Core.getHostname() + ":" + user.getEmail() + "?"
                        + "secret=" + user.newSecretOTP() + "&"
                        + "issuer=" + Core.getHostname();
                File qrcodeFile = Core.getQRCodeTempFile(code);
                imagePart.attachFile(qrcodeFile);
                imagePart.setContentID("<qrcode>");
                imagePart.setDisposition(MimeBodyPart.INLINE);
                // Join both parts.
                MimeMultipart content = new MimeMultipart();
                content.addBodyPart(htmlPart);
                content.addBodyPart(imagePart);
                // Set multiplart content.
                message.setContent(content);
                message.saveChanges();
                // Enviar mensagem.
                return Core.sendMessage(message);
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        }
    }
    
    private static boolean enviarDesbloqueio(
            String url,
            String remetente,
            String destinatario,
            Locale locale
            ) {
        if (
                Core.hasSMTP()
                && Core.hasAdminEmail()
                && Domain.isEmail(destinatario)
                && url != null
                && !NoReply.contains(destinatario, true)
                ) {
            try {
                Server.logDebug("sending unblock by e-mail.");
                if (destinatario.endsWith(".br")) {
                    locale = new Locale("pt", "BR");
                } else if (destinatario.endsWith(".pt")) {
                    locale = new Locale("pt", "PT");
                }
                InternetAddress[] recipients = InternetAddress.parse(destinatario);
                Properties props = System.getProperties();
                Session session = Session.getDefaultInstance(props);
                MimeMessage message = new MimeMessage(session);
                message.setHeader("Date", Core.getEmailDate());
                message.setFrom(Core.getAdminEmail());
                message.setReplyTo(InternetAddress.parse(remetente));
                message.addRecipients(Message.RecipientType.TO, recipients);
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    message.setSubject("Solicitação de envio SPFBL");
                } else {
                    message.setSubject("SPFBL send request");
                }
                // Corpo da mensagem.
                StringBuilder builder = new StringBuilder();
                builder.append("<html>\n");
                builder.append("  <head>\n");
                builder.append("    <meta charset=\"UTF-8\">\n");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("    <title>Solicitação de envio</title>\n");
                } else {
                    builder.append("    <title>Send request</title>\n");
                }
                builder.append("  </head>\n");
                builder.append("  <body>\n");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("       O remetente '");
                    builder.append(remetente);
                    builder.append("' deseja lhe enviar mensagens\n");
                    builder.append("       porém foi bloqueado pelo sistema como fonte de SPAM.<br>\n");
                    builder.append("       Se você confia neste remetente e quer receber mensagens dele,\n");
                    builder.append("       acesse esta URL e resolva o reCAPTCHA:<br>\n");
                } else {
                    builder.append("       The sender '");
                    builder.append(remetente);
                    builder.append("' want to send you messages\n");
                    builder.append("       but it was blocked by the system as a source of SPAM.<br>\n");
                    builder.append("       If you trust this sender and want to get his messages,\n");
                    builder.append("       go to this URL and solve the reCAPTCHA:<br>\n");
                }
                builder.append("       <a href=\"");
                builder.append(url);
                builder.append("\">");
                builder.append(url);
                builder.append("</a><br>\n");
                builder.append("    <br>\n");
                builder.append("    <small>Powered by <a target=\"_blank\" href=\"http://spfbl.net/\">SPFBL.net</a></small><br>\n");
                builder.append("  </body>\n");
                builder.append("</html>\n");
                message.setContent(builder.toString(), "text/html;charset=UTF-8");
                message.saveChanges();
                // Enviar mensagem.
                return Core.sendMessage(message);
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        } else {
            return false;
        }
    }
    
    private static boolean enviarConfirmacaoDesbloqueio(
            String destinatario,
            String remetente,
            Locale locale
            ) {
        if (
                Core.hasSMTP()
                && Core.hasAdminEmail()
                && Domain.isEmail(remetente)
                && !NoReply.contains(remetente, true)
                ) {
            try {
                Server.logDebug("sending unblock confirmation by e-mail.");
                if (remetente.endsWith(".br")) {
                    locale = new Locale("pt", "BR");
                } else if (remetente.endsWith(".pt")) {
                    locale = new Locale("pt", "PT");
                }
                InternetAddress[] recipients = InternetAddress.parse(remetente);
                Properties props = System.getProperties();
                Session session = Session.getDefaultInstance(props);
                MimeMessage message = new MimeMessage(session);
                message.setHeader("Date", Core.getEmailDate());
                message.setFrom(Core.getAdminEmail());
                message.setReplyTo(InternetAddress.parse(destinatario));
                message.addRecipients(Message.RecipientType.TO, recipients);
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    message.setSubject("Confirmação de desbloqueio SPFBL");
                } else {
                    message.setSubject("SPFBL unblocking confirmation");
                }
                // Corpo da mensagem.
                StringBuilder builder = new StringBuilder();
                builder.append("<html>\n");
                builder.append("  <head>\n");
                builder.append("    <meta charset=\"UTF-8\">\n");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("    <title>Confirmação de desbloqueio</title>\n");
                } else {
                    builder.append("    <title>Unblocking confirmation</title>\n");
                }
                builder.append("  </head>\n");
                builder.append("  <body>\n");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("       O destinatário '");
                    builder.append(destinatario);
                    builder.append("' acabou de liberar o recebimento de suas mensagens.<br>\n");
                    builder.append("       Por favor, envie novamente a mensagem anterior.<br>\n");
                } else {
                    builder.append("       The recipient '");
                    builder.append(destinatario);
                    builder.append("' just released the receipt of your message.<br>\n");
                    builder.append("       Please send the previous message again.<br>\n");
                }
                builder.append("    <br>\n");
                builder.append("    <small>Powered by <a target=\"_blank\" href=\"http://spfbl.net/\">SPFBL.net</a></small><br>\n");
                builder.append("  </body>\n");
                builder.append("</html>\n");
                message.setContent(builder.toString(), "text/html;charset=UTF-8");
                message.saveChanges();
                // Enviar mensagem.
                return Core.sendMessage(message);
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        } else {
            return false;
        }
    }
    
    private static String getUnblockHMTL(
            Locale locale,
            String message
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<html>\n");
        builder.append("  <head>\n");
        builder.append("    <meta charset=\"UTF-8\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("    <title>Página de desbloqueio do SPFBL</title>\n");
        } else {
            builder.append("    <title>SPFBL unlock page</title>\n");
        }
        if (Core.hasRecaptchaKeys()) {
//             novo reCAPCHA
//            builder.append("    <script src=\"https://www.google.com/recaptcha/api.js\" async defer></script>\n");
        }
        builder.append("  </head>\n");
        builder.append("  <body>\n");
        builder.append("    <form method=\"POST\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("       A sua mensagem está sendo rejeitada por bloqueio manual.<br>\n");
        } else {
            builder.append("       Your message is being rejected by manual block.<br>\n");
        }
        builder.append("       ");
        StringTokenizer tokenizer = new StringTokenizer(message, "\n");
        while (tokenizer.hasMoreTokens()) {
            String line = tokenizer.nextToken();
            builder.append(line);
            builder.append("<br>\n");
        }
        if (Core.hasRecaptchaKeys()) {
            String recaptchaKeySite = Core.getRecaptchaKeySite();
            String recaptchaKeySecret = Core.getRecaptchaKeySecret();
            ReCaptcha captcha = ReCaptchaFactory.newReCaptcha(recaptchaKeySite, recaptchaKeySecret, false);
            builder.append(captcha.createRecaptchaHtml(null, null));
            // novo reCAPCHA
//            builder.append("      <div class=\"g-recaptcha\" data-sitekey=\"");
//            builder.append(recaptchaKeySite);
//            builder.append("\"></div>\n");
        }
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("       <input type=\"submit\" value=\"Solicitar\">\n");
        } else {
            builder.append("       <input type=\"submit\" value=\"Request\">\n");
        }
//        if (Core.hasAdminEmail()) {
//            builder.append("       Se deseja automatizar este procedimento,<br>\n");
//            builder.append("       entre em contato com <a href=\"");
//            builder.append(Core.getAdminEmail());
//            builder.append("\">");
//            builder.append(Core.getAdminEmail());
//            builder.append("</a>.<br>\n");
//        }
        builder.append("    </form>\n");
        builder.append("    <small>Powered by <a target=\"_blank\" href=\"http://spfbl.net/\">SPFBL.net</a></small><br>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }
    
    private static String getUnblockDNSBLHMTL(
            Locale locale,
            String message
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<html>\n");
        builder.append("  <head>\n");
        builder.append("    <meta charset=\"UTF-8\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("    <title>Página de desbloqueio DNSBL</title>\n");
        } else {
            builder.append("    <title>DNSBL unblock page</title>\n");
        }
        if (Core.hasRecaptchaKeys()) {
//             novo reCAPCHA
//            builder.append("    <script src=\"https://www.google.com/recaptcha/api.js\" async defer></script>\n");
        }
        builder.append("  </head>\n");
        builder.append("  <body>\n");
        builder.append("    <form method=\"POST\">\n");
        StringTokenizer tokenizer = new StringTokenizer(message, "\n");
        while (tokenizer.hasMoreTokens()) {
            String line = tokenizer.nextToken();
            builder.append(line);
            builder.append("<br>\n");
        }
        if (Core.hasRecaptchaKeys()) {
            String recaptchaKeySite = Core.getRecaptchaKeySite();
            String recaptchaKeySecret = Core.getRecaptchaKeySecret();
            ReCaptcha captcha = ReCaptchaFactory.newReCaptcha(recaptchaKeySite, recaptchaKeySecret, false);
            builder.append(captcha.createRecaptchaHtml(null, null));
            // novo reCAPCHA
//            builder.append("      <div class=\"g-recaptcha\" data-sitekey=\"");
//            builder.append(recaptchaKeySite);
//            builder.append("\"></div>\n");
        }
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("       <input type=\"submit\" value=\"Desbloquear\">\n");
        } else {
            builder.append("       <input type=\"submit\" value=\"Unblock\">\n");
        }
        builder.append("    </form>\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("    <small>Powered by <a target=\"_blank\" href=\"http://spfbl.net/dnsbl/\">SPFBL.net</a></small><br>\n");
        } else {
            builder.append("    <small>Powered by <a target=\"_blank\" href=\"http://spfbl.net/dnsbl/english/\">SPFBL.net</a></small><br>\n");
        }
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }
    
    private static String getWhiteHMTL(
            Locale locale,
            String message
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<html>\n");
        builder.append("  <head>\n");
        builder.append("    <meta charset=\"UTF-8\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("    <title>Página de desbloqueio do SPFBL</title>\n");
        } else {
            builder.append("    <title>SPFBL unblock page</title>\n");
        }
        if (Core.hasRecaptchaKeys()) {
//             novo reCAPCHA
//            builder.append("    <script src=\"https://www.google.com/recaptcha/api.js\" async defer></script>\n");
        }
        builder.append("  </head>\n");
        builder.append("  <body>\n");
        builder.append("    <form method=\"POST\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("       Este remetente foi bloqueado no sistema SPFBL.<br>\n");
        } else {
            builder.append("       The sender has been blocked in SPFBL system.<br>\n");
        }
        builder.append("       ");
//        builder.append("       Para liberar o recebimento da mensagem, resolva o desafio reCAPTCHA abaixo.<br>\n");
        StringTokenizer tokenizer = new StringTokenizer(message, "\n");
        while (tokenizer.hasMoreTokens()) {
            String line = tokenizer.nextToken();
            builder.append(line);
            builder.append("<br>\n");
        }
        if (Core.hasRecaptchaKeys()) {
            String recaptchaKeySite = Core.getRecaptchaKeySite();
            String recaptchaKeySecret = Core.getRecaptchaKeySecret();
            ReCaptcha captcha = ReCaptchaFactory.newReCaptcha(recaptchaKeySite, recaptchaKeySecret, false);
            builder.append(captcha.createRecaptchaHtml(null, null));
            // novo reCAPCHA
//            builder.append("      <div class=\"g-recaptcha\" data-sitekey=\"");
//            builder.append(recaptchaKeySite);
//            builder.append("\"></div>\n");
        }
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("       <input type=\"submit\" value=\"Liberar\">\n");
        } else {
            builder.append("       <input type=\"submit\" value=\"Release\">\n");
        }
        builder.append("    </form>\n");
        builder.append("    <small>Powered by <a target=\"_blank\" href=\"http://spfbl.net/\">SPFBL.net</a></small><br>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }
    
    private static String getLoginOTPHMTL(
            Locale locale,
            String message
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<html>\n");
        builder.append("  <head>\n");
        builder.append("    <meta charset=\"UTF-8\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("    <title>Página de login do SPFBL</title>\n");
        } else {
            builder.append("    <title>SPFBL login page</title>\n");
        }
        builder.append("  </head>\n");
        builder.append("  <body>\n");
        builder.append("    <form method=\"POST\">\n");
        StringTokenizer tokenizer = new StringTokenizer(message, "\n");
        while (tokenizer.hasMoreTokens()) {
            String line = tokenizer.nextToken();
            builder.append(line);
            builder.append("<br>\n");
        }
        builder.append("      <input type=\"password\" name=\"otp\" autofocus>\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("       <input type=\"submit\" value=\"Entrar\">\n");
        } else {
            builder.append("       <input type=\"submit\" value=\"Login\">\n");
        }
        builder.append("    </form>\n");
        builder.append("    <small>Powered by <a target=\"_blank\" href=\"http://spfbl.net/\">SPFBL.net</a></small><br>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }
    
    private static String getSendOTPHMTL(
            Locale locale,
            String message
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<html>\n");
        builder.append("  <head>\n");
        builder.append("    <meta charset=\"UTF-8\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("    <title>Página de login do SPFBL</title>\n");
        } else {
            builder.append("    <title>SPFBL login page</title>\n");
        }
        if (Core.hasRecaptchaKeys()) {
//             novo reCAPCHA
//            builder.append("    <script src=\"https://www.google.com/recaptcha/api.js\" async defer></script>\n");
        }
        builder.append("  </head>\n");
        builder.append("  <body>\n");
        builder.append("    <form method=\"POST\">\n");
        StringTokenizer tokenizer = new StringTokenizer(message, "\n");
        while (tokenizer.hasMoreTokens()) {
            String line = tokenizer.nextToken();
            builder.append(line);
            builder.append("<br>\n");
        }
        if (Core.hasRecaptchaKeys()) {
            String recaptchaKeySite = Core.getRecaptchaKeySite();
            String recaptchaKeySecret = Core.getRecaptchaKeySecret();
            ReCaptcha captcha = ReCaptchaFactory.newReCaptcha(recaptchaKeySite, recaptchaKeySecret, false);
            builder.append(captcha.createRecaptchaHtml(null, null));
            // novo reCAPCHA
//            builder.append("      <div class=\"g-recaptcha\" data-sitekey=\"");
//            builder.append(recaptchaKeySite);
//            builder.append("\"></div>\n");
        }
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("       <input type=\"submit\" value=\"Enviar\">\n");
        } else {
            builder.append("       <input type=\"submit\" value=\"Send\">\n");
        }
        builder.append("    </form>\n");
        builder.append("    <small>Powered by <a target=\"_blank\" href=\"http://spfbl.net/\">SPFBL.net</a></small><br>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private static String getReleaseHMTL(
            Locale locale,
            String message
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<html>\n");
        builder.append("  <head>\n");
        builder.append("    <meta charset=\"UTF-8\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("    <title>Página de liberação SPFBL</title>\n");
        } else {
            builder.append("    <title>SPFBL release page</title>\n");
        }
        if (Core.hasRecaptchaKeys()) {
//             novo reCAPCHA
//            builder.append("    <script src=\"https://www.google.com/recaptcha/api.js\" async defer></script>\n");
        }
        builder.append("  </head>\n");
        builder.append("  <body>\n");
        builder.append("    <form method=\"POST\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("       O recebimento da sua mensagem está sendo atrasado por suspeita de SPAM.<br>\n");
        } else {
            builder.append("       The receipt of your message is being delayed by SPAM suspect.<br>\n");
        }
        builder.append("       ");
        StringTokenizer tokenizer = new StringTokenizer(message, "\n");
        while (tokenizer.hasMoreTokens()) {
            String line = tokenizer.nextToken();
            builder.append(line);
            builder.append("<br>\n");
        }
        if (Core.hasRecaptchaKeys()) {
            String recaptchaKeySite = Core.getRecaptchaKeySite();
            String recaptchaKeySecret = Core.getRecaptchaKeySecret();
            ReCaptcha captcha = ReCaptchaFactory.newReCaptcha(recaptchaKeySite, recaptchaKeySecret, false);
            builder.append(captcha.createRecaptchaHtml(null, null));
            // novo reCAPCHA
//            builder.append("      <div class=\"g-recaptcha\" data-sitekey=\"");
//            builder.append(recaptchaKeySite);
//            builder.append("\"></div>\n");
        }
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("       <input type=\"submit\" value=\"Liberar\">\n");
        } else {
            builder.append("       <input type=\"submit\" value=\"Release\">\n");
        }
        builder.append("    </form>\n");
        builder.append("    <small>Powered by <a target=\"_blank\" href=\"http://spfbl.net/\">SPFBL.net</a></small><br>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }
    
    private static String getHoldingHMTL(
            Locale locale,
            String message
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<html>\n");
        builder.append("  <head>\n");
        builder.append("    <meta charset=\"UTF-8\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("    <title>Página de liberação SPFBL</title>\n");
        } else {
            builder.append("    <title>SPFBL release page</title>\n");
        }
        if (Core.hasRecaptchaKeys()) {
//             novo reCAPCHA
//            builder.append("    <script src=\"https://www.google.com/recaptcha/api.js\" async defer></script>\n");
        }
        builder.append("  </head>\n");
        builder.append("  <body>\n");
        builder.append("    <form method=\"POST\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("       A mensagem retida por suspeita de SPAM.<br>\n");
        } else {
            builder.append("       The message retained on suspicion of SPAM.<br>\n");
        }
        builder.append("       ");
        StringTokenizer tokenizer = new StringTokenizer(message, "\n");
        while (tokenizer.hasMoreTokens()) {
            String line = tokenizer.nextToken();
            builder.append(line);
            builder.append("<br>\n");
        }
        if (Core.hasRecaptchaKeys()) {
            String recaptchaKeySite = Core.getRecaptchaKeySite();
            String recaptchaKeySecret = Core.getRecaptchaKeySecret();
            ReCaptcha captcha = ReCaptchaFactory.newReCaptcha(recaptchaKeySite, recaptchaKeySecret, false);
            builder.append(captcha.createRecaptchaHtml(null, null));
            // novo reCAPCHA
//            builder.append("      <div class=\"g-recaptcha\" data-sitekey=\"");
//            builder.append(recaptchaKeySite);
//            builder.append("\"></div>\n");
        }
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("       <input type=\"submit\" value=\"Solicitar\">\n");
        } else {
            builder.append("       <input type=\"submit\" value=\"Request\">\n");
        }
        builder.append("    </form>\n");
        builder.append("    <small>Powered by <a target=\"_blank\" href=\"http://spfbl.net/\">SPFBL.net</a></small><br>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }
    
    private static String getBlockHMTL(
            Locale locale,
            String message1,
            String message2
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<html>\n");
        builder.append("  <head>\n");
        builder.append("    <meta charset=\"UTF-8\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("    <title>Página de bloqueio SPFBL</title>\n");
        } else {
            builder.append("    <title>SPFBL block page</title>\n");
        }
        if (Core.hasRecaptchaKeys()) {
//             novo reCAPCHA
//            builder.append("    <script src=\"https://www.google.com/recaptcha/api.js\" async defer></script>\n");
        }
        builder.append("  </head>\n");
        builder.append("  <body>\n");
        builder.append("    <form method=\"POST\">\n");
        builder.append("       <p>");
        StringTokenizer tokenizer1 = new StringTokenizer(message1, "\n");
        while (tokenizer1.hasMoreTokens()) {
            String line = tokenizer1.nextToken();
            builder.append(line);
            builder.append("<br>\n");
        }
        builder.append("       <p>");
        StringTokenizer tokenizer2 = new StringTokenizer(message2, "\n");
        while (tokenizer2.hasMoreTokens()) {
            String line = tokenizer2.nextToken();
            builder.append(line);
            builder.append("<br>\n");
        }
        if (Core.hasRecaptchaKeys()) {
            String recaptchaKeySite = Core.getRecaptchaKeySite();
            String recaptchaKeySecret = Core.getRecaptchaKeySecret();
            ReCaptcha captcha = ReCaptchaFactory.newReCaptcha(recaptchaKeySite, recaptchaKeySecret, false);
            builder.append(captcha.createRecaptchaHtml(null, null));
            // novo reCAPCHA
//            builder.append("      <div class=\"g-recaptcha\" data-sitekey=\"");
//            builder.append(recaptchaKeySite);
//            builder.append("\"></div>\n");
        }
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("       <input type=\"submit\" value=\"Bloquear\">\n");
        } else {
            builder.append("       <input type=\"submit\" value=\"Block\">\n");
        }
        builder.append("    </form>\n");
        builder.append("    <small>Powered by <a target=\"_blank\" href=\"http://spfbl.net/\">SPFBL.net</a></small><br>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }
    
    private static String getRedirectHMTL(
            String title,
            String message,
            String page,
            int time
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<html>\n");
        builder.append("  <head>\n");
        builder.append("    <meta charset=\"UTF-8\" http-equiv=\"refresh\" content=\"");
        builder.append(time);
        builder.append(";url=");
        builder.append(page);
        builder.append("\">\n");
        builder.append("    <title>");
        builder.append(title);
        builder.append("</title>\n");
        builder.append("  </head>\n");
        builder.append("  <body>\n");
        builder.append("    ");
        if (message != null) {
            builder.append(message.replace("\n", "<br>\n"));
        }
//        StringTokenizer tokenizer = new StringTokenizer(message, "\n");
//        while (tokenizer.hasMoreTokens()) {
//            String line = tokenizer.nextToken();
//            builder.append(line);
//            builder.append("<br>\n");
//        }
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private static String getMessageHMTL(
            String title,
            String message
    ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<html>\n");
        builder.append("  <head>\n");
        builder.append("    <meta charset=\"UTF-8\">\n");
        builder.append("    <title>");
        builder.append(title);
        builder.append("</title>\n");
        builder.append("  </head>\n");
        builder.append("  <body>\n");
        builder.append("    ");
        if (message != null) {
            builder.append(message.replace("\n", "<br>\n"));
        }
//        StringTokenizer tokenizer = new StringTokenizer(message, "\n");
//        while (tokenizer.hasMoreTokens()) {
//            String line = tokenizer.nextToken();
//            builder.append(line);
//            builder.append("<br>\n");
//        }
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }
    
    private static TreeSet<String> getPostmaterSet(String query) {
        TreeSet<String> emailSet = new TreeSet<String>();
        if (Subnet.isValidIP(query)) {
            String ip = Subnet.normalizeIP(query);
            Reverse reverse = Reverse.get(ip);
            TreeSet<String> reverseSet = reverse.getAddressSet();
            if (!reverseSet.isEmpty()) {
                String hostname = reverseSet.pollFirst();
                do  {
                    hostname = Domain.normalizeHostname(hostname, true);
                    if (!hostname.endsWith(".arpa")) {
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
                            if (!Generic.contains(hostname) && SPF.matchHELO(ip, hostname)) {
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
        } else if (Domain.isHostname(query)) {
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
    
    private static String getDNSBLHTML(
            Locale locale,
            Client client,
            String query,
            String message
            ) {
        StringBuilder builder = new StringBuilder();
        if (client != null && client.hasEmail() && client.getEmail().endsWith(".br")) {
            locale = new Locale("pt", "BR");
        } else if (client != null && client.hasEmail() && client.getEmail().endsWith(".pt")) {
            locale = new Locale("pt", "PT");
        }
        builder.append("<html>\n");
        builder.append("  <head>\n");
        builder.append("    <meta charset=\"UTF-8\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("    <title>Página de checagem DNSBL</title>\n");
        } else {
            builder.append("    <title>DNSBL check page</title>\n");
        }
        builder.append("  </head>\n");
        builder.append("  <body>\n");
        builder.append("    <iframe data-aa='455818' src='//ad.a-ads.com/455818?size=468x60' scrolling='no' style='width:468px; height:60px; border:0px; padding:0;overflow:hidden' allowtransparency='true'></iframe>");
        builder.append("    <p>");
        builder.append(message);
        builder.append("\n");
        TreeSet<String> emailSet = new TreeSet<String>();
        if (Subnet.isValidIP(query)) {
            String ip = Subnet.normalizeIP(query);
            if (Subnet.isReservedIP(ip)) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("    <p>Este é um IP reservado e por este motivo não é abordado nesta lista.\n");
                } else {
                    builder.append("    <p>This is a reserved IP and for this reason is not addressed in this list.\n");
                }
            } else {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("    <p>Reversos encontrados:");
                } else {
                    builder.append("    <p>rDNS found:");
                }
                boolean generic = false;
                Reverse reverse = Reverse.get(ip, true);
                TreeSet<String> reverseSet = reverse.getAddressSet();
                if (reverseSet.isEmpty()) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append(" nenhum<br>\n");
                    } else {
                        builder.append(" none<br>\n");
                    }
                    builder.append("    <br>\n");
                } else {
                    builder.append("<br>\n");
                    builder.append("    <ul>\n");
                    String hostname = reverseSet.pollFirst();
                    do  {
                        hostname = Domain.normalizeHostname(hostname, false);
                        builder.append("      <li>&lt;");
                        builder.append(hostname);
                        builder.append("&gt; ");
                        if (SPF.matchHELO(ip, hostname, true)) {
                            String domain;
                            try {
                                domain = Domain.extractDomain(hostname, false);
                            } catch (ProcessException ex) {
                                domain = null;
                            }
                            if (domain == null) {
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    builder.append("domínio reservado.</li>\n");
                                } else {
                                    builder.append("reserved domain.</li>\n");
                                }
                            } else if (hostname.endsWith(".arpa")) {
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    builder.append("domínio reservado.</li>\n");
                                } else {
                                    builder.append("reserved domain.</li>\n");
                                }
                            } else if (Generic.contains(domain)) {
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    builder.append("domínio genérico.</li>\n");
                                } else {
                                    builder.append("generic domain.</li>\n");
                                }
                            } else if (Generic.contains(hostname)) {
                                emailSet.add("postmaster@" + domain);
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    builder.append("reverso genérico.</li>\n");
                                } else {
                                    builder.append("generic rDNS.</li>\n");
                                }
                            } else {
                                int loop = 0;
                                String subdominio = hostname;
                                while (loop++ < 32 && subdominio.endsWith(domain)) {
                                    emailSet.add("postmaster@" + subdominio);
                                    int index = subdominio.indexOf('.', 1) + 1;
                                    subdominio = subdominio.substring(index);
                                }
                                if (locale.getLanguage().toLowerCase().equals("pt")) {
                                    builder.append("FCrDNS válido.</li>\n");
                                } else {
                                    builder.append("valid FCrDNS.</li>\n");
                                }
                            }
                        } else {
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                builder.append("FCrDNS inválido.</li>\n");
                            } else {
                                builder.append("invalid FCrDNS.</li>\n");
                            }
                        }
                    } while ((hostname = reverseSet.pollFirst()) != null);
                    builder.append("    </ul>\n");
                }
                Distribution distribution;
                if ((distribution = SPF.getDistribution(ip, true)).isNotGreen(ip)) {
                    float probability = distribution.getSpamProbability(ip);
                    boolean blocked = Block.containsCIDR(ip);
                    if (blocked || distribution.isRed(ip)) {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            builder.append("    Este IP ");
                            if (blocked) {
                                builder.append("foi bloqueado");
                            } else {
                                builder.append("está listado");
                            }
                            builder.append(" por má reputação com ");
                            builder.append(Core.PERCENT_FORMAT.format(probability));
                            builder.append(" de pontos negativos do volume total de envio.<br>\n");
                            builder.append("    <br>\n");
                            builder.append("    Para que este IP possa ser removido desta lista,<br>\n");
                            builder.append("    é necessário que o MTA de origem reduza o volume de envios para os destinatários<br>\n");
                            builder.append("    cuja rejeição SMTP tenha prefixo '5.7.1 SPFBL &lt;message&gt;'.<br>\n");
                            builder.append("    <br>\n");
                            builder.append("    Cada rejeição SMTP com este prefixo gera automaticamente um novo ponto negativo neste sistema,");
                            builder.append("    onde este ponto expira em uma semana.<br>\n");
                            builder.append("    <br>\n");
                            builder.append("    O motivo da rejeição pode ser compreendida pela mensagem que acompanha o prefixo.<br>\n");
                        } else {
                            builder.append("    This IP ");
                            if (blocked) {
                                builder.append("was blocked");
                            } else {
                                builder.append("is listed");
                            }
                            builder.append(" by poor reputation in ");
                            builder.append(Core.PERCENT_FORMAT.format(probability));
                            builder.append(" of negative points of total amount sent.<br>\n");
                            builder.append("    <br>\n");
                            builder.append("    In order for this IP to be removed from this list,<br>\n");
                            builder.append("    it is necessary that the source MTA reduce the sending volume for the recipients<br>\n");
                            builder.append("    whose SMTP rejection has the prefix '5.7.1 SPFBL &lt;message&gt;'.<br>\n");
                            builder.append("    <br>\n");
                            builder.append("    Each SMTP rejection with this prefix automatically generates a new negative point in this system,");
                            builder.append("    where this point expires in a week.<br>\n");
                            builder.append("    <br>\n");
                            builder.append("    The reason for the rejection can be understood by the message that follows the prefix.<br>\n");
                        }
                    } else {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            builder.append("    Este IP não está listado neste sistema porém sua reputação está com ");
                            builder.append(Core.PERCENT_FORMAT.format(probability));
                            builder.append(" de pontos negativos do volume total de envio.<br>\n");
                            builder.append("    <br>\n");
                            builder.append("    Se esta reputação tiver aumento significativo na quantidade de pontos negativos,");
                            builder.append("    este IP será automaticamente listado neste sistema.<br>\n");
                            builder.append("    <br>\n");
                            builder.append("    Para evitar que isto ocorra, reduza os envios cuja rejeição SMTP");
                            builder.append("    tenha prefixo '5.7.1 SPFBL &lt;message&gt;'.<br>\n");
                            builder.append("    <br>\n");
                            builder.append("    Cada rejeição SMTP com este prefixo");
                            builder.append("    gera automaticamente um novo ponto negativo neste sistema.<br>\n");
                            builder.append("    <br>\n");
                            builder.append("    O motivo da rejeição pode ser compreendida pela mensagem que acompanha o prefixo.<br>\n");
                        } else {
                            builder.append("    This IP is not listed in this system but its reputation is with ");
                            builder.append(Core.PERCENT_FORMAT.format(probability));
                            builder.append(" of negative points of total sending.<br>\n");
                            builder.append("    <br>\n");
                            builder.append("    If this reputation have significant increase in the number of negative points,");
                            builder.append("    this IP will automatically be listed in the system.<br>\n");
                            builder.append("    <br>\n");
                            builder.append("    To prevent this from occurring, reduce sending whose SMTP rejection");
                            builder.append("    has prefix '5.7.1 SPFBL &lt;message&gt;'.<br>\n");
                            builder.append("    <br>\n");
                            builder.append("    Each SMTP rejection with this prefix");
                            builder.append("    automatically generates a new negative point in this system.<br>\n");
                            builder.append("    <br>\n");
                            builder.append("    The reason for the rejection can be understood by the message that follows the prefix.<br>\n");
                        }
                    }
                } else if (emailSet.isEmpty()) {
                    boolean blocked = Block.containsCIDR(ip);
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        if (blocked) {
                            builder.append("    Este IP foi bloqueado por não ter reverso válido.<br>\n");
                        } else {
                            builder.append("    Este IP não está bloqueado porém não tem um reverso válido.<br>\n");
                        }
                        if (generic) {
                            builder.append("    Não serão aceitos reversos genéricos, veja o <a href=\"http://www.spamcannibal.org/statsgeneric.html\">critério de registro genérico</a>.<br>\n");
                        }
                        builder.append("    Cadastre um DNS reverso válido para este IP, que aponte para o mesmo IP.<br>\n");
                        if (blocked) {
                            builder.append("    O DNS reverso deve estar sob seu próprio domínio para que a liberação seja efetivada.<br>\n");
                        } else {
                            builder.append("    Qualquer IP com FCrDNS inválido pode ser incluido a qualquer momento nesta lista.<br>\n");
                        }
                    } else {
                        if (blocked) {
                            builder.append("    This IP has been blocked because have none valid rDNS.<br>\n");
                        } else {
                            builder.append("    This IP isn't blocked but have none valid rDNS.<br>\n");
                        }
                        if (generic) {
                            builder.append("    Generic rDNS will not be accepted, see the <a href=\"http://www.spamcannibal.org/statsgeneric.html\">generic PTR record criteria</a>.<br>\n");
                        }
                        builder.append("    Register a valid rDNS for this IP, which points to the same IP.<br>\n");
                        if (blocked) {
                            builder.append("    The rDNS must be registered under your own domain for us to be able to delist your system.<br>\n");
                        } else {
                            builder.append("    Any IP with invalid FCrDNS can be included at any time in this list.<br>\n");
                        }
                    }
                } else if (Block.containsCIDR(ip)) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("    Este IP foi bloqueado, porém a reputação dele não está mais ruim.<br>\n");
                        builder.append("    <br>\n");
                        builder.append("    E-mails para envio de chave de desbloqueio:<br>\n");
                    } else {
                        builder.append("    This IP has been blocked, but it's reputation is not bad anymore.<br>\n");
                        builder.append("    <br>\n");
                        builder.append("    E-mails to send unblock key:<br>\n");
                    }
                    builder.append("    <ul>\n");
                    if (
                            client != null &&
                            client.hasPermission(DNSBL) &&
                            client.hasEmail()
                            ) {
                        emailSet.add(client.getEmail());
                    }
                    TreeSet<String> sendSet = new TreeSet<String>();
                    String email = emailSet.pollFirst();
                    do  {
                        builder.append("      <li>&lt;");
                        builder.append(email);
                        builder.append("&gt; ");
                        if (Trap.contaisAnything(email)) {
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                builder.append("inexistente.</li>\n");
                            } else {
                                builder.append("non-existent.</li>\n");
                            }
                        } else if (NoReply.contains(email, false)) {
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                builder.append("não permitido.</li>\n");
                            } else {
                                builder.append("not permitted.</li>\n");
                            }
                        } else {
                            sendSet.add(email);
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                builder.append("permitido.</li>\n");
                            } else {
                                builder.append("permitted.</li>\n");
                            }
                        }
                    } while ((email = emailSet.pollFirst()) != null);
                    builder.append("    </ul>\n");
                    if (sendSet.isEmpty()) {
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            builder.append("    Nenhum e-mail do responsável pelo IP é permitido neste sistema.<br>\n");
                        } else {
                            builder.append("    None of the responsible for IP has e-mail permitted under this system.<br>\n");
                        }
                    } else {
                        builder.append("    <form method=\"POST\">\n");
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            builder.append("      Para que a chave de desbloqueio seja enviada,<br>\n");
                            builder.append("      selecione o endereço de e-mail do responsável pelo IP:<br>\n");
                        } else {
                            builder.append("      For the release key to be sent,<br>\n");
                            builder.append("      select the e-mail address responsible for this IP:<br>\n");
                        }
                        for (String send : sendSet) {
                            builder.append("      <input type=\"radio\" name=\"identifier\" value=\"");
                            builder.append(send);
                            builder.append("\">");
                            builder.append(send);
                            builder.append("<br>\n");
                        }
                        builder.append("      <br>\n");
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            builder.append("      O DNS reverso do IP deve estar sob seu próprio domínio.<br>\n");
                            builder.append("      Não aceitamos DNS reversos com domínios de terceiros.<br>\n");
                        } else {
                            builder.append("      The rDNS must be registered under your own domain.<br>\n");
                            builder.append("      We do not accept rDNS with third-party domains.<br>\n");
                        }
                        if (Core.hasRecaptchaKeys()) {
                            builder.append("      <br>\n");
                            if (locale.getLanguage().toLowerCase().equals("pt")) {
                                builder.append("      Para que sua solicitação seja aceita,<br>\n");
                                builder.append("      resolva o desafio reCAPTCHA abaixo.<br>\n");
                            } else {
                                builder.append("      For your request to be accepted,<br>\n");
                                builder.append("      please solve the reCAPTCHA below.<br>\n");
                            }
                            String recaptchaKeySite = Core.getRecaptchaKeySite();
                            String recaptchaKeySecret = Core.getRecaptchaKeySecret();
                            ReCaptcha captcha = ReCaptchaFactory.newReCaptcha(recaptchaKeySite, recaptchaKeySecret, false);
                            builder.append("      ");
                            builder.append(captcha.createRecaptchaHtml(null, null).replace("\r", ""));
                            // novo reCAPCHA
                //            builder.append("      <div class=\"g-recaptcha\" data-sitekey=\"");
                //            builder.append(recaptchaKeySite);
                //            builder.append("\"></div>\n");
                        }
                        if (locale.getLanguage().toLowerCase().equals("pt")) {
                            builder.append("      <input type=\"submit\" value=\"Solicitar\">\n");
                        } else {
                            builder.append("      <input type=\"submit\" value=\"Request\">\n");
                        }
                        builder.append("    </form>\n");
                    }
                } else {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("    Nenhum bloqueio foi encontrado para este IP.<br>\n");
                        builder.append("    Se este IP estiver sendo rejeitado por algum MTA,<br>\n");
                        builder.append("    aguarde a propagação de DNS deste serviço.<br>\n");
                        builder.append("    O tempo de propagação pode levar alguns dias.<br>\n");
                    } else {
                        builder.append("    No block was found for this IP.<br>\n");
                        builder.append("    If this IP is being rejected by some MTA,<br>\n");
                        builder.append("    wait for the DNS propagation of this service.<br>\n");
                        builder.append("    The propagation time can take a few days.<br>\n");
                    }
                }
            }
        } else if (Domain.isHostname(query)) {
            Distribution distribution;
            query = Domain.normalizeHostname(query, true);
            if ((distribution = SPF.getDistribution(query, true)).isNotGreen(query)) {
                float probability = distribution.getSpamProbability(query);
                boolean blocked = Block.containsDomain(query, false);
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("    Este domínio ");
                    if (blocked) {
                        builder.append("foi bloqueado");
                    } else {
                        builder.append("está listado");
                    }
                    builder.append(" por má reputação com ");
                    builder.append(Core.PERCENT_FORMAT.format(probability));
                    builder.append(" de pontos negativos do volume total de envio.<br>\n");
                    builder.append("    <br>\n");
                    builder.append("    Para que este domínio possa ser removido desta lista,<br>\n");
                    builder.append("    é necessário que o MTA de origem reduza o volume de envios para os destinatários<br>\n");
                    builder.append("    cuja rejeição SMTP tenha prefixo '5.7.1 SPFBL &lt;message&gt;'.<br>\n");
                    builder.append("    <br>\n");
                    builder.append("    Cada rejeição SMTP com este prefixo gera automaticamente um novo ponto negativo neste sistema,");
                    builder.append("    onde este expira em uma semana.<br>\n");
                    builder.append("    <br>\n");
                    builder.append("    O motivo da rejeição pode ser compreendida pela mensagem que acompanha o prefixo.<br>\n");
                } else {
                    builder.append("    This domain is ");
                    if (blocked) {
                        builder.append("was blocked");
                    } else {
                        builder.append("is listed");
                    }
                    builder.append(" by poor reputation in ");
                    builder.append(Core.PERCENT_FORMAT.format(probability));
                    builder.append(" of negative points of total sending.<br>\n");
                    builder.append("    <br>\n");
                    builder.append("    In order for this domain can be removed from this list,<br>\n");
                    builder.append("    it is necessary that the source MTA reduce the sending volume for the recipients<br>\n");
                    builder.append("    whose SMTP rejection has prefix '5.7.1 SPFBL &lt;message&gt;'.<br>\n");
                    builder.append("    <br>\n");
                    builder.append("    Each SMTP rejection with this prefix automatically generates a new negative point in this system,");
                    builder.append("    where this point expires in a week.<br>\n");
                    builder.append("    <br>\n");
                    builder.append("    The reason for the rejection can be understood by the message that follows the prefix.<br>\n");
                }
            } else if (Block.containsDomain(query, false)) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("    Este domínio está listado por bloqueio manual.<br>\n");
                    if (Core.hasAdminEmail()) {
                        builder.append("    <br>\n");
                        builder.append("    Para que este domínio seja removido desta lista,<br>\n");
                        builder.append("    é necessário enviar uma solicitação para ");
                        builder.append(Core.getAdminEmail());
                        builder.append(".<br>\n");
                    }
                } else {
                    builder.append("    This domain is listed by manual block.<br>\n");
                    if (Core.hasAdminEmail()) {
                        builder.append("    <br>\n");
                        builder.append("    In order for this domain to be removed from this list,<br>\n");
                        builder.append("    You must send a request to ");
                        builder.append(Core.getAdminEmail());
                        builder.append(".<br>\n");
                    }
                }
            } else {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("    Nenhum bloqueio foi encontrado para este domínio.<br>\n");
                } else {
                    builder.append("    No block was found for this domain.<br>\n");
                }
            }
        }
        builder.append("    <br>\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("    <small>Powered by <a target=\"_blank\" href=\"http://spfbl.net/dnsbl/\">SPFBL.net</a></small><br>\n");
        } else {
            builder.append("    <small>Powered by <a target=\"_blank\" href=\"http://spfbl.net/dnsbl/english/\">SPFBL.net</a></small><br>\n");
        }
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }
    
    private static String getRedirectHTML(String url) {
        StringBuilder builder = new StringBuilder();
        builder.append("<html>\n");
        builder.append("  <head>\n");
        builder.append("    <meta http-equiv=\"refresh\" content=\"0; url=");
        builder.append(url);
        builder.append("\" />\n");
        builder.append("  </head>\n");
        builder.append("</html>\n");
        return builder.toString();
    }
    
    private static String getControlPanel(
            Locale locale,
            Query query,
            long time
            ) {
        DateFormat dateFormat = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM, locale);
        GregorianCalendar calendar = new GregorianCalendar();
        calendar.setTimeInMillis(time);
        if (query.getUserEmail().endsWith(".br")) {
            locale = new Locale("pt", "BR");
        } else if (query.getUserEmail().endsWith(".pt")) {
            locale = new Locale("pt", "PT");
        }
        StringBuilder builder = new StringBuilder();
        builder.append("<html>\n");
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
        builder.append("      }\n");
        builder.append("      .white:hover {\n");
        builder.append("          background-color: #4CAF50;\n");
        builder.append("          color: white;\n");
        builder.append("      }\n");
        builder.append("      .block {\n");
        builder.append("          background-color: white; \n");
        builder.append("          color: black; \n");
        builder.append("          border: 2px solid #f44336;\n");
        builder.append("          font-weight: bold;\n");
        builder.append("      }\n");
        builder.append("      .block:hover {\n");
        builder.append("          background-color: #f44336;\n");
        builder.append("          color: white;\n");
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
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("    <b>Recebe por:</b> ");
        } else {
            builder.append("    <b>Receives for:</b> ");
        }
        String validator = query.getValidator(true);
        Situation situationWhite = query.getSenderWhiteSituation();
        Situation situationBlock = query.getSenderBlockSituation();
        try {
            TreeSet<String> mxDomainSet = query.getSenderMXDomainSet();
            if (mxDomainSet.isEmpty()) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("nenhum sistema");
                } else {
                    builder.append("no system");
                }
            } else {
                builder.append(mxDomainSet);
            }
        } catch (NameNotFoundException ex) {
            validator = null;
            situationWhite = query.getOriginWhiteSituation();
            situationBlock = query.getOriginBlockSituation();
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("domínio inexistente");
            } else {
                builder.append("non-existent domain");
            }
        } catch (NamingException ex) {
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("erro ao tentar consultar");
            } else {
                builder.append("error when trying to query");
            }
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
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("    <b>Politica vigente:</b> ");
        } else {
            builder.append("    <b>Current policy:</b> ");
        }
        String recipient = query.getRecipient();
        Long trapTime = query.getTrapTime();
        boolean blocked = false;
        if (trapTime == null && situationWhite == Situation.SAME) {
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("entrega prioritária na mesma situação, exceto malware");
            } else {
                builder.append("priority delivery of ");
                builder.append(query.getSenderSimplified(false, true));
                builder.append(" in the same situation, except malware");
            }
        } else if (trapTime == null && situationWhite == Situation.AUTHENTIC) {
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("entrega prioritária de ");
                builder.append(query.getSenderSimplified(false, true));
                builder.append(" quando comprovadamente autêntico, exceto malware");
            } else {
                builder.append("priority delivery of ");
                builder.append(query.getSenderSimplified(false, true));
                builder.append(" when proven authentic, except malware");
            }
            if (query.isBlock()) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append(", porém bloqueado para outras situações");
                } else {
                    builder.append(", however blocked to other situations");
                }
            }
        } else if (trapTime == null && situationWhite == Situation.ZONE) {
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("entrega prioritária de ");
                builder.append(query.getSenderSimplified(false, true));
                builder.append(" quando disparado por ");
            } else {
                builder.append("priority delivery of ");
                builder.append(query.getSenderSimplified(false, true));
                builder.append(" when shot by ");
            }
            builder.append(validator);
            if (query.isBlock()) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append(", porém bloqueado para outras situações");
                } else {
                    builder.append(", however blocked to other situations");
                }
            }
        } else if (trapTime == null && situationWhite == Situation.IP) {
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("entrega prioritária de ");
                builder.append(query.getSenderSimplified(false, true));
                builder.append(" when shot by IP ");
            } else {
                builder.append("priority delivery of ");
                builder.append(query.getSenderSimplified(false, true));
                builder.append(" when coming from the IP ");
            }
            builder.append(validator);
            if (query.isBlock()) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append(", porém bloqueado para outras situações");
                } else {
                    builder.append(", however blocked to other situations");
                }
            }
        } else if (trapTime == null && situationWhite == Situation.ORIGIN) {
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("entrega prioritária pela mesma origem");
            } else {
                builder.append("priority delivery the same origin");
            }
        } else if (situationBlock == Situation.DOMAIN) {
            blocked = true;
            String domain = query.getSenderSimplified(true, false);
            if (domain == null) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("bloquear na mesma situação");
                } else {
                    builder.append("block in the same situation");
                }
            } else {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("bloquear ");
                    builder.append(domain);
                    builder.append(" em qualquer situação");
                } else {
                    builder.append("block ");
                    builder.append(domain);
                    builder.append(" in any situation");
                }
            }
        } else if (situationBlock == Situation.ALL) {
            blocked = true;
            String domain = query.getOriginDomain(false);
            if (domain == null) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("bloquear na mesma situação");
                } else {
                    builder.append("block in the same situation");
                }
            } else {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("bloquear ");
                    builder.append(domain);
                    builder.append(" em qualquer situação");
                } else {
                    builder.append("block ");
                    builder.append(domain);
                    builder.append(" in any situation");
                }
            }
        } else if (situationBlock == Situation.SAME) {
            blocked = true;
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("bloquear na mesma situação");
            } else {
                builder.append("block in the same situation");
            }
        } else if ((situationBlock == Situation.ZONE || situationBlock == Situation.IP) && !query.getQualifierName().equals("PASS")) {
            blocked = true;
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("bloquear ");
                builder.append(query.getSenderDomain(false));
                builder.append(" quando não for autêntico");
            } else {
                builder.append("block ");
                builder.append(query.getSenderDomain(false));
                builder.append(" when not authentic");
            }
        } else if (situationBlock == Situation.ORIGIN) {
            blocked = true;
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("bloquear quando disparado pela mesma origem");
            } else {
                builder.append("block when shot by the same source");
            }
        } else if (query.isFail()) {
            blocked = true;
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("rejeitar entrega por falsificação");
            } else {
                builder.append("reject delivery of forgery");
            }
        } else if (trapTime != null) {
            if (System.currentTimeMillis() > trapTime) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("descartar mensagem por armadilha");
                } else {
                    builder.append("discard message by spamtrap");
                }
            } else {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("rejeitar entrega por destinatário inexistente");
                } else {
                    builder.append("reject delivery by inexistent recipient");
                }
            }
        } else if (query.hasRed()) {
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("marcar como suspeita e entregar, sem considerar o conteúdo");
            } else {
                builder.append("flag as suspected and deliver, regardless of content");
            }
        } else if (query.isSoftfail() || query.hasYellow()) {
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("atrasar entrega na mesma situação, sem considerar o conteúdo");
            } else {
                builder.append("delay delivery in the same situation, regardless of content");
            }
        } else {
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("aceitar entrega na mesma situação, sem considerar o conteúdo");
            } else {
                builder.append("accept delivery in the same situation, regardless of content");
            }
        }
        builder.append(".<br>\n");
        builder.append("    <form method=\"POST\">\n");
        if (validator == null) {
            if (situationWhite != Situation.ORIGIN) {
                builder.append("      <button type=\"submit\" class=\"white\" name=\"POLICY\" value=\"WHITE_ORIGIN\">");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("Entrega prioritária quando for da mesma origem\n");
                } else {
                    builder.append("Priority delivery when the same origin\n");
                }
                builder.append("</button>\n");
            }
            if (situationWhite != Situation.NONE || situationBlock != Situation.ALL) {
                if (situationBlock != Situation.ORIGIN) {
                    builder.append("      <button type=\"submit\" class=\"block\" name=\"POLICY\" value=\"BLOCK_ORIGIN\">");
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("Bloquear se for da mesma origem");
                    } else {
                        builder.append("Block if the same origin");
                    }
                    builder.append("</button>\n");
                }
                String domain = query.getOriginDomain(false);
                if (domain != null) {
                    builder.append("      <button type=\"submit\" class=\"block\" name=\"POLICY\" value=\"BLOCK_ALL\">");
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("Bloquear ");
                        builder.append(domain);
                        builder.append(" em qualquer situação");
                    } else {
                        builder.append("Block ");
                        builder.append(domain);
                        builder.append(" in any situation");
                    }
                    builder.append("</button>\n");
                }
            }
        } else if (validator.equals("PASS")) {
            if (situationWhite != Situation.AUTHENTIC) {
                builder.append("      <button type=\"submit\" class=\"white\" name=\"POLICY\" value=\"WHITE_AUTHENTIC\">");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("Entrega prioritária quando comprovadamente autêntico\n");
                } else {
                    builder.append("Priority delivery when proven authentic\n");
                }
                builder.append("</button>\n");
            }
        } else if (Subnet.isValidIP(validator)) {
            if (situationWhite != Situation.IP) {
                builder.append("      <button type=\"submit\" class=\"white\" name=\"POLICY\" value=\"WHITE_IP\">");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("Entrega prioritária quando disparado pelo IP ");
                } else {
                    builder.append("Priority delivery when shot by IP ");
                }
                builder.append(validator);
                builder.append("</button>\n");
            }
            if (situationBlock != Situation.IP && situationBlock != Situation.DOMAIN) {
                builder.append("      <button type=\"submit\" class=\"block\" name=\"POLICY\" value=\"BLOCK_IP\">");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("Bloquear ");
                    builder.append(query.getSenderDomain(false));
                    builder.append(" quando não for autêntico");
                } else {
                    builder.append("Block ");
                    builder.append(query.getSenderDomain(false));
                    builder.append(" when not authentic");
                }
                builder.append("</button>\n");
            }
        } else if (Domain.isHostname(validator)) {
            if (situationWhite != Situation.ZONE) {
                builder.append("      <button type=\"submit\" class=\"white\" name=\"POLICY\" value=\"WHITE_ZONE\">");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("Entrega prioritária quando disparado por ");
                } else {
                    builder.append("Priority delivery when shot by ");
                }
                builder.append(validator);
                builder.append("</button>\n");
            }
            if (situationBlock != Situation.ZONE && situationBlock != Situation.DOMAIN) {
                builder.append("      <button type=\"submit\" class=\"block\" name=\"POLICY\" value=\"BLOCK_ZONE\">");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("Bloquear ");
                    builder.append(query.getSenderDomain(false));
                    builder.append(" quando não for autêntico");
                } else {
                    builder.append("Block ");
                    builder.append(query.getSenderDomain(false));
                    builder.append(" when not authentic");
                }
                builder.append("</button>\n");
            }
        }
        if (situationBlock != Situation.DOMAIN && validator != null) {
            builder.append("      <button type=\"submit\" class=\"block\" name=\"POLICY\" value=\"BLOCK_DOMAIN\">");
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("Bloquear ");
                builder.append(query.getSenderSimplified(true, false));
                builder.append(" em qualquer situação");
            } else {
                builder.append("Block ");
                builder.append(query.getSenderSimplified(true, false));
                builder.append(" in any situation");
            }
            builder.append("</button>\n");
        }
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
        }
        builder.append("    </form>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }
    
    private static void buildQueryRow(
            Locale locale,
            StringBuilder builder,
            DateFormat dateFormat,
            GregorianCalendar calendar,
            long time,
            User.Query query,
            boolean highlight
    ) {
        if (query != null) {
            calendar.setTimeInMillis(time);
            String ip = query.getIP();
            String hostname = query.getValidHostname();
            String sender = query.getSender();
            String from = query.getFrom();
            String replyto = query.getReplyTo();
            String subject = query.getSubject();
            String malware = query.getMalware();
            String recipient = query.getRecipient();
            String result = query.getResult();
            if (query.getUserEmail().endsWith(".br")) {
                locale = new Locale("pt", "BR");
            } else if (query.getUserEmail().endsWith(".pt")) {
                locale = new Locale("pt", "PT");
            }
            builder.append("        <tr id=\"");
            builder.append(time);
            builder.append("\"");
            if (highlight) {
                builder.append(" class=\"highlight\"");
            } else {
                builder.append(" class=\"click\"");
            }
            builder.append(" onclick=\"view('");
            builder.append(time);
            builder.append("')\">\n");
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("          <td style=\"width:120px;\">");
            } else {
                builder.append("          <td style=\"width:160px;\">");
            }
            builder.append(dateFormat.format(calendar.getTime()));
            builder.append("<br>");
            builder.append(query.getClient());
            builder.append("</td>\n");
            builder.append("          <td>");
            if (hostname == null) {
                String helo = query.getHELO();
                if (helo == null) {
                    builder.append(ip);
                } else if (Subnet.isValidIP(helo)) {
                    builder.append(ip);
                } else {
                    builder.append(ip);
                    builder.append("<br>");
                    builder.append("<strike>");
                    builder.append(helo);
                    builder.append("</strike>");
                }
            } else if (Generic.containsDomain(hostname)) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("<small><i>Genérico</i></small>");
                } else {
                    builder.append("<small><i>Generic</i></small>");
                }
                builder.append("<br>");
                builder.append(hostname);
            } else if (Provider.containsDomain(hostname)) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("<small><i>Provedor</i></small>");
                } else {
                    builder.append("<small><i>Provider</i></small>");
                }
                builder.append("<br>");
                builder.append(hostname);
            } else {
                builder.append(hostname);
            }
            builder.append("</td>\n");
            TreeSet<String> senderSet = new TreeSet<String>();
            builder.append("          <td>");
            if (sender == null) {
                builder.append("MAILER-DAEMON");
            } else {
                senderSet.add(sender);
                String qualifier = query.getQualifierName();
                if (qualifier.equals("PASS")) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("<small><i>Comprovadamente autêntico</i></small>");
                    } else {
                        builder.append("<small><i>Proved genuine</i></small>");
                    }
                } else if (qualifier.equals("FAIL")) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("<small><i>Comprovadamente falso</i></small>");
                    } else {
                        builder.append("<small><i>Proved false</i></small>");
                    }
                } else if (qualifier.equals("SOFTFAIL")) {
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("<small><i>Pode ser falso</i></small>");
                    } else {
                        builder.append("<small><i>May be false</i></small>");
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
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("<small><b>Assunto:</b> ");
                } else {
                    builder.append("<small><b>Subject:</b> ");
                }
                builder.append(subject);
                builder.append("</small>");
                builder.append("<hr style=\"height:0px;visibility:hidden;margin-bottom:0px;\">");
            }
            if (malware == null) {
                TreeSet<String> linkSet = query.getLinkSet();
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
                        builder.append(link);
                        builder.append("</b></font>");
                    } else {
                        builder.append(link);
                    }
                    while (!linkSet.isEmpty()) {
                        builder.append("<br>");
                        link = linkSet.pollFirst();
                        if (query.isLinkBlocked(link)) {
                            builder.append("<font color=\"DarkRed\"><b>");
                            builder.append(link);
                            builder.append("</b></font>");
                        } else {
                            builder.append(link);
                        }
                    }
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
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("Rejeitada pelo conteúdo");
                } else {
                    builder.append("Rejected by content");
                }
                if (recipient != null) {
                    builder.append("<br>");
                    builder.append(recipient);
                }
            } else if (result.equals("BLOCK") || result.equals("BLOCKED")) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("Rejeitada por bloqueio");
                } else {
                    builder.append("Rejected by blocking");
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
                    builder.append("Descartado pela armadilha");
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
                    builder.append("Entrega prioritária");
                } else {
                    builder.append("Priority delivery");
                }
                if (recipient != null) {
                    builder.append("<br>");
                    builder.append(recipient);
                }
            } else if (result.equals("ACCEPT")) {
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("Entrega aceita");
                } else {
                    builder.append("Accepted for delivery");
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
                    builder.append("Entrega retida");
                } else {
                    builder.append("Delivery retained");
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
            User user,
            Long begin
            ) {
        StringBuilder builder = new StringBuilder();
        if (begin == null) {
            if (user.getEmail().endsWith(".br")) {
                locale = new Locale("pt", "BR");
            } else if (user.getEmail().endsWith(".pt")) {
                locale = new Locale("pt", "PT");
            }
            builder.append("<html>\n");
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
            builder.append("        margin:180px 0px 0px 0px;\n");
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
            builder.append("    </style>\n");
            // JavaScript functions.
            TreeSet<Long> queryKeySet = user.getQueryKeySet(null);
            builder.append("    <script type=\"text/javascript\" src=\"https://ajax.googleapis.com/ajax/libs/jquery/2.1.3/jquery.min.js\"></script>\n");
            builder.append("    <script type=\"text/javascript\">\n");
            builder.append("      window.onbeforeunload = function () {\n");
            builder.append("        window.scrollTo(0, 0);\n");
            builder.append("      }\n");
            builder.append("      var last = ");
            if (queryKeySet.isEmpty()) {
                builder.append(0);
            } else {
                builder.append(queryKeySet.last());
            }
            builder.append(";\n");
            builder.append("      function view(query) {\n");
            builder.append("        if (last != query) {\n");
            builder.append("          var viewer = document.getElementById('viewer');\n");
            builder.append("          viewer.addEventListener('load', function() {\n");
            builder.append("            document.getElementById(last).className = 'tr';\n");
            builder.append("            document.getElementById(last).className = 'click';\n");
            builder.append("            document.getElementById(query).className = 'highlight';\n");
            builder.append("            last = query;\n");
            builder.append("          });\n");
            builder.append("          viewer.src = '");
            builder.append(Core.getURL());
            builder.append("' + query;\n");
            builder.append("        }\n");
            builder.append("      }\n");
            builder.append("      function more(query) {\n");
            builder.append("        var rowMore = document.getElementById('rowMore');\n");
            builder.append("        rowMore.onclick = '';\n");
            builder.append("        rowMore.className = 'tr';\n");
            builder.append("        var columnMore = document.getElementById('columnMore');\n");
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("        columnMore.innerHTML = 'carregando mais registros';\n");
            } else {
                builder.append("        columnMore.innerHTML = 'loading more records';\n");
            }
            builder.append("        $.post('");
            builder.append(Core.getURL());
            builder.append(user.getEmail());
            builder.append("', {begin:query},\n");
            builder.append("        function(data, status){;\n");
            builder.append("          if (status == 'success') {\n");
            builder.append("            rowMore.parentNode.removeChild(rowMore);\n");
            builder.append("            $('#tableBody').append(data);\n");
            builder.append("          } else {\n");
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("            alert('Houve uma falha de sistema ao tentar realizar esta operação.');\n");
            } else {
                builder.append("            alert('There was a system crash while trying to perform this operation.');\n");
            }
            builder.append("          }\n");
            builder.append("        });\n");
            builder.append("      }\n");
            builder.append("    </script>\n");
            builder.append("  </head>\n");
            // Body.
            builder.append("  <body>\n");
            builder.append("    <div class=\"header\">\n");
            if (queryKeySet.isEmpty()) {
                builder.append("      <iframe id=\"viewer\" src=\"about:blank\"></iframe>\n");
            } else {
                builder.append("      <iframe id=\"viewer\" src=\"");
                builder.append(Core.getURL());
                builder.append(queryKeySet.last());
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
            if (queryKeySet.isEmpty()) {
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
                GregorianCalendar calendar = new GregorianCalendar();
                Long nextQuery = null;
                while (queryKeySet.size() > 1024) {
                    nextQuery = queryKeySet.pollFirst();
                }
                builder.append("    <table>\n");
                builder.append("      <tbody id=\"tableBody\">\n");
                for (Long time : queryKeySet.descendingSet()) {
                    User.Query query = user.getQuery(time);
                    boolean highlight = time.equals(queryKeySet.last());
                    buildQueryRow(locale, builder, dateFormat, calendar, time, query, highlight);
                }
                if (nextQuery == null) {
                    builder.append("      <tr>\n");
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("        <td colspan=\"5\" align=\"center\">não foram encontrados outros registros</td>\n");
                    } else {
                        builder.append("        <td colspan=\"5\" align=\"center\">no more records found</td>\n");
                    }
                    builder.append("      </tr>\n");
                } else {
                    builder.append("        <tr id=\"rowMore\" class=\"click\" onclick=\"more('");
                    builder.append(nextQuery);
                    builder.append("')\">\n");
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("          <td id=\"columnMore\" colspan=\"5\" align=\"center\">clique para ver mais registros</td>\n");
                    } else {
                        builder.append("          <td id=\"columnMore\" colspan=\"5\" align=\"center\">click to see more records</td>\n");
                    }
                    builder.append("        </tr>\n");
                }
                builder.append("      </tbody>\n");
                builder.append("    </table>\n");
            }
            builder.append("    <small>Powered by <a target=\"_blank\" href=\"http://spfbl.net/\">SPFBL.net</a></small><br>\n");
            builder.append("  </body>\n");
            builder.append("</html>\n");
        } else {
            TreeSet<Long> queryKeySet = user.getQueryKeySet(begin);
            if (queryKeySet.isEmpty()) {
                builder.append("        <tr>\n");
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    builder.append("          <td colspan=\"5\" align=\"center\">nenhum registro encontrado</td>\n");
                } else {
                    builder.append("          <td colspan=\"5\" align=\"center\">no records found</td>\n");
                }
                builder.append("        </tr>\n");
            } else {
                DateFormat dateFormat = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM, locale);
                GregorianCalendar calendar = new GregorianCalendar();
                Long nextQuery = null;
                while (queryKeySet.size() > 1024) {
                    nextQuery = queryKeySet.pollFirst();
                }
                for (Long time : queryKeySet.descendingSet()) {
                    User.Query query = user.getQuery(time);
                    buildQueryRow(locale, builder, dateFormat, calendar, time, query, false);
                }
                if (nextQuery == null) {
                    builder.append("        <tr>\n");
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("          <td colspan=\"5\" align=\"center\">não foram encontrados outros registros</td>\n");
                    } else {
                        builder.append("          <td colspan=\"5\" align=\"center\">no more records found</td>\n");
                    }
                    builder.append("        </tr>\n");
                } else {
                    builder.append("        <tr id=\"rowMore\" class=\"click\" onclick=\"more('");
                    builder.append(nextQuery);
                    builder.append("')\">\n");
                    if (locale.getLanguage().toLowerCase().equals("pt")) {
                        builder.append("          <td id=\"columnMore\" colspan=\"5\" align=\"center\">clique para ver mais registros</td>\n");
                    } else {
                        builder.append("          <td id=\"columnMore\" colspan=\"5\" align=\"center\">click to see more records</td>\n");
                    }
                    builder.append("        </tr>\n");
                }
            }
        }
        return builder.toString();
    }
    
    private static String getMainHTML(
            Locale locale,
            String message,
            String value
            ) {
        StringBuilder builder = new StringBuilder();
        builder.append("<html>\n");
        builder.append("  <head>\n");
        builder.append("    <meta charset=\"UTF-8\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("    <title>Serviço SPFBL</title>\n");
        } else {
            builder.append("    <title>SPFBL service</title>\n");
        }
        builder.append("  </head>\n");
        builder.append("  <body>\n");
        builder.append("    ");
        builder.append(message);
        builder.append("<br>\n");
        builder.append("    <br>\n");
        if (Core.hasPortDNSBL()) {
            builder.append("    <form method=\"POST\">\n");
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("      Para consultar uma reputação no serviço DNSBL, digite um IP ou um domínio:<br>\n");
            } else {
                builder.append("      To query for reputation in the DNSBL service, type an IP or domain:<br>\n");
            }
            builder.append("      <input type=\"text\" name=\"query\" value=\"");
            builder.append(value);
            builder.append("\" autofocus>\n");
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("      <input type=\"submit\" value=\"Consultar\">\n");
            } else {
                builder.append("      <input type=\"submit\" value=\"Query\">\n");
            }
            builder.append("    </form>\n");
        } else {
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("      Nenhuma ferramenta está disponível neste momento.<br>\n");
            } else {
                builder.append("      No tool is available at this time.<br>\n");
            }
        }
        builder.append("    <br>\n");
        builder.append("    <small>Powered by <a target=\"_blank\" href=\"http://spfbl.net/\">SPFBL.net</a></small><br>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private static String getComplainHMTL(
            Locale locale,
            TreeSet<String> tokenSet,
            TreeSet<String> selectionSet,
            String message,
            boolean whiteBlockForm
            ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<html>\n");
        builder.append("  <head>\n");
        builder.append("    <meta charset=\"UTF-8\">\n");
        if (locale.getLanguage().toLowerCase().equals("pt")) {
            builder.append("    <title>Página de denuncia SPFBL</title>\n");
        } else {
            builder.append("    <title>SPFBL complaint page</title>\n");
        }
        if (Core.hasRecaptchaKeys()) {
//             novo reCAPCHA
//            builder.append("    <script src=\"https://www.google.com/recaptcha/api.js\" async defer></script>\n");
        }
        builder.append("  </head>\n");
        builder.append("  <body>\n");
        builder.append("    ");
        builder.append(message);
        builder.append("<br>\n");
        builder.append("    <br>\n");
        if (whiteBlockForm) {
            writeBlockFormHTML(locale, builder, tokenSet, selectionSet);
        }
        builder.append("    <small>Powered by <a target=\"_blank\" href=\"http://spfbl.net/\">SPFBL.net</a></small><br>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private static void writeBlockFormHTML(
            Locale locale,
            StringBuilder builder,
            TreeSet<String> tokenSet,
            TreeSet<String> selectionSet
            ) throws ProcessException {
        if (!tokenSet.isEmpty()) {
            builder.append("    <form method=\"POST\">\n");
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("      Se você deseja não receber mais mensagens desta origem no futuro,<br>\n");
                builder.append("      selecione os identificadores que devem ser bloqueados definitivamente:<br>\n");
            } else {
                builder.append("      If you want to stop receiving messages from the source in the future,<br>\n");
                builder.append("      select identifiers that should definitely be blocked:<br>\n");
            }
            for (String identifier : tokenSet) {
                builder.append("      <input type=\"checkbox\" name=\"identifier\" value=\"");
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
                    builder.append("      Para que sua solicitação seja aceita,<br>\n");
                    builder.append("      resolva o desafio reCAPTCHA abaixo.<br>\n");
                } else {
                    builder.append("      For your request to be accepted,<br>\n");
                    builder.append("      please solve the reCAPTCHA below.<br>\n");
                }
                String recaptchaKeySite = Core.getRecaptchaKeySite();
                String recaptchaKeySecret = Core.getRecaptchaKeySecret();
                ReCaptcha captcha = ReCaptchaFactory.newReCaptcha(recaptchaKeySite, recaptchaKeySecret, false);
                builder.append("      ");
                builder.append(captcha.createRecaptchaHtml(null, null).replace("\r", ""));
                // novo reCAPCHA
    //            builder.append("      <div class=\"g-recaptcha\" data-sitekey=\"");
    //            builder.append(recaptchaKeySite);
    //            builder.append("\"></div>\n");
            }
            if (locale.getLanguage().toLowerCase().equals("pt")) {
                builder.append("      <input type=\"submit\" value=\"Bloquear\">\n");
            } else {
                builder.append("      <input type=\"submit\" value=\"Block\">\n");
            }
            builder.append("    </form>\n");
        }
    }

    private static void response(int code, String response,
            HttpExchange exchange) throws IOException {
        byte[] byteArray = response.getBytes("UTF-8");
        exchange.sendResponseHeaders(code, byteArray.length);
        OutputStream os = exchange.getResponseBody();
        try {
            os.write(byteArray);
        } finally {
            os.close();
        }
    }

    /**
     * Inicialização do serviço.
     */
    @Override
    public void run() {
        SERVER.start();
        Server.logInfo("listening on HTTP port " + PORT + ".");
    }

    @Override
    protected void close() throws Exception {
        Server.logDebug("unbinding HTTP on port " + PORT + "...");
        SERVER.stop(1);
        Server.logInfo("HTTP server closed.");
    }
}
