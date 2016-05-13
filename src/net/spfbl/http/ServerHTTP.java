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
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.TreeSet;
import javax.mail.Message;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import net.spfbl.data.Block;
import net.spfbl.core.Client;
import static net.spfbl.core.Client.Permission.DNSBL;
import net.spfbl.core.Core;
import net.spfbl.core.Defer;
import net.spfbl.core.ProcessException;
import net.spfbl.core.Reverse;
import net.spfbl.data.NoReply;
import net.spfbl.data.Provider;
import net.spfbl.data.White;
import net.spfbl.spf.SPF;
import net.spfbl.spf.SPF.Distribution;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import net.tanesha.recaptcha.ReCaptcha;
import net.tanesha.recaptcha.ReCaptchaFactory;
import net.tanesha.recaptcha.ReCaptchaResponse;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.commons.lang3.StringEscapeUtils;

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
    }

    public String getSpamURL() {
        if (HOSTNAME == null) {
            return null;
        } else {
            return "http://" + HOSTNAME + (PORT == 80 ? "" : ":" + PORT) + "/spam/";
        }
    }

    public String getReleaseURL() {
        if (HOSTNAME == null) {
            return null;
        } else {
            return "http://" + HOSTNAME + (PORT == 80 ? "" : ":" + PORT) + "/release/";
        }
    }
    
    public String getDNSBLURL() {
        if (HOSTNAME == null) {
            return null;
        } else {
            return "http://" + HOSTNAME + (PORT == 80 ? "" : ":" + PORT) + "/dnsbl/";
        }
    }
    
    public String getUnblockURL() {
        if (HOSTNAME == null) {
            return null;
        } else {
            return "http://" + HOSTNAME + (PORT == 80 ? "" : ":" + PORT) + "/unblock/";
        }
    }
    
    public String getWhiteURL() {
        if (HOSTNAME == null) {
            return null;
        } else {
            return "http://" + HOSTNAME + (PORT == 80 ? "" : ":" + PORT) + "/white/";
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

    private static String getOrigin(HttpExchange exchange) {
        InetSocketAddress socketAddress = exchange.getRemoteAddress();
        InetAddress address = socketAddress.getAddress();
        Client client = Client.get(address);
        if (client == null) {
            return address.getHostAddress();
        } else {
            return address.getHostAddress() + ' ' + client.getDomain();
        }
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
            return null;
        } else {
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
                } else {
                    map.put(key, value);
                }
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
            int index = language.indexOf(';');
            if (index == -1) {
                locale = Locale.forLanguageTag(language);
                q = 1.0f;
            } else {
                String value = language.substring(0,index).trim();
                locale = Locale.forLanguageTag(value);
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
            return locale.toLanguageTag();
        }
    }
    
    private static Locale getLocale(String acceptLanguage) {
        if (acceptLanguage == null) {
            return Locale.US;
        } else {
            TreeSet<Language> languageSet = new TreeSet<Language>();
            StringTokenizer tokenizer = new StringTokenizer(acceptLanguage, ",");
            while (tokenizer.hasMoreTokens()) {
                Language language = new Language(tokenizer.nextToken());
                languageSet.add(language);
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
                Client client = getClient(exchange);
                String origin = getOrigin(exchange);
                int code;
                String result;
                String type;
                if (request.equals("POST")) {
                    if (command.startsWith("/dnsbl/")) {
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
                                        String remoteAddress = getRemoteAddress(exchange);
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
                                    if (locale.getLanguage().equals("pt")) {
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
                                    TreeSet<String> emailSet = (TreeSet) parameterMap.get("identifier");
                                    for (String email : emailSet) {
                                        if (postmaterSet.contains(email)) {
                                            String url = Core.getUnblockURL(email, ip);
                                            if (enviarDesbloqueioDNSBL(url, ip, email)) {
                                                if (locale.getLanguage().equals("pt")) {
                                                    message = "Chave de desbloqueio enviada com sucesso.";
                                                } else {
                                                    message = "Unblocking key successfully sent.";
                                                }
                                            }
                                        }
                                    }
                                    type = "DNSBL";
                                    code = 200;
                                    String title;
                                    if (locale.getLanguage().equals("pt")) {
                                        title = "Página de checagem DNSBL";
                                    } else {
                                        title = "DNSBL check page";
                                    }
                                    result = getMessageHMTL(title, message);
                                } else {
                                    type = "DNSBL";
                                    code = 200;
                                    String message;
                                    if (locale.getLanguage().equals("pt")) {
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
                                if (locale.getLanguage().equals("pt")) {
                                    message = "O e-mail do responsável pelo IP não foi definido.";
                                } else {
                                    message = "The e-mail of responsible IP was not set.";
                                }
                                result = getDNSBLHTML(locale, client, ip, message);
                            }
                        } else {
                            type = "DNSBL";
                            code = 500;
                            String title;
                            if (locale.getLanguage().equals("pt")) {
                                title = "Página de checagem DNSBL";
                            } else {
                                title = "DNSBL check page";
                            }
                            String message;
                            if (locale.getLanguage().equals("pt")) {
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
                                        String remoteAddress = getRemoteAddress(exchange);
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
                                    result = "Bloqueados: " + blockSet + " >" + recipient + "\n";
                                } else {
                                    type = "HTTPC";
                                    code = 200;
                                    String message = "O desafio do reCAPTCHA não foi resolvido.";
                                    result = getComplainHMTL(tokenSet, identifierSet, message, true);
                                }
                            } else {
                                type = "HTTPC";
                                code = 500;
                                result = "Identificadores indefinidos.\n";
                            }
                        } catch (Exception ex) {
                            type = "HTTPC";
                            code = 500;
                            result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                        }
                    } else if (command.startsWith("/release/")) {
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
                                result = getMessageHMTL(
                                        "Página de liberação do SPFBL",
                                        "Este ticket de liberação está vencido."
                                        );
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
                                        String remoteAddress = getRemoteAddress(exchange);
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
                                    String title = "Página de liberação do SPFBL";
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
                                        message = "Sua mensagem foi liberada com sucesso.";
                                    } else {
                                        message = "Sua mensagem já havia sido liberada.";
                                    }
                                    type = "DEFER";
                                    code = 200;
                                    result = getMessageHMTL(title, message);
                                } else {
                                    type = "DEFER";
                                    code = 200;
                                    result = getReleaseHMTL(
                                            "O desafio reCAPTCHA não foi resolvido. "
                                            + "Tente novamente."
                                            );
                                }
                            }
                        } catch (Exception ex) {
                            type = "SPFSP";
                            code = 500;
                            result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                        }
                    } else if (command.startsWith("/unblock/")) {
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
                                result = getMessageHMTL(
                                        "Página de desbloqueio do SPFBL",
                                        "Este ticket de desbloqueio está vencido."
                                        );
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
                                        String remoteAddress = getRemoteAddress(exchange);
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
                                        String title = "Página de desbloqueio do SPFBL";
                                        String message;
                                        if (Block.clearCIDR(ip, clientTicket)) {
                                            message = "O IP " + ip + " foi desbloqueado com sucesso.";
                                        } else {
                                            message = "O IP " + ip + " já estava desbloqueado.";
                                        }
                                        type = "BLOCK";
                                        code = 200;
                                        result = getMessageHMTL(title, message);
                                    } else {
                                        type = "BLOCK";
                                        code = 200;
                                        String message;
                                        if (locale.getLanguage().equals("pt")) {
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
                                    String white = clientTicket + origem + ";PASS>" + recipient;
                                    String url = Core.getWhiteURL(white, clientTicket, ip, sender, hostname, recipient);
                                    String title = "Página de desbloqueio do SPFBL";
                                    String message;
                                    if (enviarDesbloqueio(url, sender, recipient)) {
                                        Block.addExact(white);
                                        message = "A solicitação de desbloqueio foi "
                                                + "enviada para o destinatário '" + recipient + "'.\n"
                                                + "Aguarde pelo desbloqueio sem enviar novas mensagens.";
                                    } else {
                                        message = "Não foi possível enviar a solicitação de "
                                                + "desbloqueio para o destinatário "
                                                + "'" + recipient + "' devido a problemas técnicos.";
                                    }
                                    type = "BLOCK";
                                    code = 200;
                                    result = getMessageHMTL(title, message);
                                } else {
                                    type = "BLOCK";
                                    code = 200;
                                    result = getUnblockHMTL(
                                            "O desafio reCAPTCHA não foi resolvido. "
                                            + "Tente novamente."
                                            );
                                }
                            }
                        } catch (Exception ex) {
                            type = "SPFSP";
                            code = 500;
                            result = ex.getMessage() == null ? "Undefined error." : ex.getMessage() + "\n";
                        }
                    } else if (command.startsWith("/white/")) {
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
                                result = getMessageHMTL(
                                        "Página de desbloqueio do SPFBL",
                                        "Este ticket de desbloqueio está vencido."
                                        );
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
                                        String remoteAddress = getRemoteAddress(exchange);
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
                                    String title = "Página de desbloqueio do SPFBL";
                                    String message;
                                    if (White.addExact(white)) {
                                        Block.clear(client, ip, sender, hostname, "PASS", recipient);
                                        message = "O desbloqueio do remetente '" + sender + "' foi efetuado com sucesso.";
                                    } else {
                                        message = "O desbloqueio do remetente '" + sender + "' já havia sido evetudao.";
                                    }
                                    type = "WHITE";
                                    code = 200;
                                    result = getMessageHMTL(title, message);
                                } else {
                                    type = "WHITE";
                                    code = 200;
                                    result = getWhiteHMTL(
                                            "O desafio reCAPTCHA não foi resolvido. "
                                            + "Tente novamente."
                                            );
                                }
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
                } else if (request.equals("GET")) {
                    if (command.startsWith("/dnsbl/")) {
                        int index = command.indexOf('/', 1) + 1;
                        String query = command.substring(index);
                        if (Subnet.isValidIP(query)) {
                            type = "DNSBL";
                            code = 200;
                            String message;
                            if (locale.getLanguage().equals("pt")) {
                                message = "Resultado da checagem DNSBL do IP " + query + ".";
                            } else {
                                message = "DNSBL checking the result of IP " + query + ".";
                            }
                            result = getDNSBLHTML(locale, client, query, message);
                        } else if (Domain.isHostname(query)) {
                            type = "DNSBL";
                            code = 200;
                            String message;
                            if (locale.getLanguage().equals("pt")) {
                                message = "Resutado da checagem DNSBL do domínio '" + query + "'.";
                            } else {
                                message = "DNSBL checking the result of domain " + query + ".";
                            }
                            result = getDNSBLHTML(locale, client, query, message);
                        } else {
                            type = "DNSBL";
                            code = 500;
                            String title;
                            if (locale.getLanguage().equals("pt")) {
                                title = "Página de checagem DNSBL";
                            } else {
                                title = "DNSBL check page";
                            }
                            String message;
                            if (locale.getLanguage().equals("pt")) {
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
                                message = "A mensagem já havia sido denunciada antes.";
                            } else {
                                String clientTicket = SPF.getClient(ticket);
                                String sender = SPF.getSender(ticket);
                                if (clientTicket != null && sender != null && recipient != null) {
                                    if (White.dropExact(clientTicket + ":" + sender + ";PASS>" + recipient)) {
                                        Server.logDebug("WHITE DROP " + clientTicket + ":" + sender + ";PASS>" + recipient);
                                    }
                                }
                                message = "A mensagem foi denunciada com sucesso.";
                            }
                            for (String token : complainSet) {
                                if (!Subnet.isValidIP(token)) {
                                    selectionSet.add(token);
                                }
                            }
                            type = "SPFSP";
                            code = 200;
                            result = getComplainHMTL(tokenSet, selectionSet, message, whiteBlockForm);
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
                                result = getMessageHMTL(
                                        "Página de liberação do SPFBL",
                                        "Este ticket de liberação está vencido."
                                        );
                            } else {
                                String id = registry.substring(index + 1);
                                Defer defer = Defer.getDefer(date, id);
                                if (defer == null) {
                                    type = "DEFER";
                                    code = 500;
                                    result = getMessageHMTL(
                                            "Página de liberação do SPFBL",
                                            "Este ticket de liberação não existe ou já foi liberado antes."
                                            );
                                } else if (defer.isReleased()) {
                                    type = "DEFER";
                                    code = 200;
                                    result = getMessageHMTL(
                                            "Página de liberação do SPFBL",
                                            "Sua mensagem já havia sido liberada."
                                            );
                                } else {
                                    type = "DEFER";
                                    code = 200;
                                    result = getReleaseHMTL(
                                            "Para liberar o recebimento da mensagem, "
                                            + "resolva o desafio reCAPTCHA abaixo."
                                            );
                                }
                            }
                        } catch (Exception ex) {
                            type = "DEFER";
                            code = 500;
                            result = getMessageHMTL(
                                    "Página de liberação do SPFBL",
                                    "Ocorreu um erro no processamento desta solicitação: "
                                    + ex.getMessage() == null ? "undefined error." : ex.getMessage()
                                    );
                        }
                    } else if (command.startsWith("/unblock/")) {
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
                                if (locale.getLanguage().equals("pt")) {
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
                                clientTicket = clientTicket == null ? "" : clientTicket + ':';
                                String mx = Domain.extractHost(sender, true);
                                String origem = Provider.containsExact(mx) ? sender : mx;
                                if (System.currentTimeMillis() - date.getTime() > 432000000) {
                                    // Ticket vencido com mais de 5 dias.
                                    type = "BLOCK";
                                    code = 500;
                                    result = getMessageHMTL(
                                            "Página de desbloqueio do SPFBL",
                                            "Este ticket de desbloqueio está vencido."
                                            );
                                } else if (sender == null || recipient == null) {
                                    type = "BLOCK";
                                    code = 500;
                                    result = getMessageHMTL(
                                            "Página de desbloqueio do SPFBL",
                                            "Este ticket de desbloqueio não "
                                            + "contém remetente e destinatário."
                                            );
                                } else if (White.containsExact(clientTicket + origem + ";PASS>" + recipient)) {
                                    type = "BLOCK";
                                    code = 200;
                                    result = getMessageHMTL(
                                            "Página de desbloqueio do SPFBL",
                                            "O destinatário '" + recipient + "' "
                                            + "já autorizou o recebimento de mensagens "
                                            + "do remetente '" + sender + "'."
                                            );
                                } else if (Block.containsExact(clientTicket + origem + ";PASS>" + recipient)) {
                                    type = "BLOCK";
                                    code = 200;
                                    result = getMessageHMTL(
                                            "Página de desbloqueio do SPFBL",
                                            "O destinatário '" + recipient + "' "
                                            + "não decidiu se quer receber mensagens "
                                            + "do remetente '" + sender + "'.\n"
                                            + "Para que a reputação deste remetente "
                                            + "não seja prejudicada neste sistema, "
                                            + "é necessário que ele pare de tentar "
                                            + "enviar mensagens para este "
                                            + "destinatário até a sua decisão.\n"
                                            + "Cada tentativa de envio por ele, "
                                            + "conta um ponto negativo na "
                                            + "reputação dele deste sistema."
                                            );
                                } else {
                                    type = "BLOCK";
                                    code = 200;
                                    result = getUnblockHMTL(
                                                "Para solicitar o desbloqueio do remetente '" + sender + "'\n"
                                                + "diretamente para o destinatário '" + recipient + "',\n"
                                                + "resolva o desafio reCAPTCHA abaixo."
                                                );
                                }
                            }
                        } catch (Exception ex) {
                            ex.printStackTrace();
                            type = "BLOCK";
                            code = 500;
                            result = getMessageHMTL(
                                    "Página de desbloqueio do SPFBL",
                                    "Ocorreu um erro no processamento desta solicitação: "
                                    + ex.getMessage() == null ? "undefined error." : ex.getMessage()
                                    );
                        }
                    } else if (command.startsWith("/white/")) {
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
                                result = getMessageHMTL(
                                        "Página de desbloqueio do SPFBL",
                                        "Este ticket de desbloqueio está vencido."
                                        );
                            } else if (White.containsExact(white)) {
                                type = "WHITE";
                                code = 200;
                                result = getMessageHMTL(
                                        "Página de desbloqueio do SPFBL",
                                        "Já houve liberação deste remetente '"
                                        + sender + "' pelo destinatário '"
                                        + recipient + "'."
                                        );
                            } else {
                                type = "WHITE";
                                code = 200;
                                result = getWhiteHMTL(
                                        "Para desbloquear este remetente '"
                                        + sender + "',\n"
                                        + "resolva o desafio reCAPTCHA abaixo."
                                        );
                            }
                        } catch (Exception ex) {
                            type = "WHITE";
                            code = 500;
                            result = getMessageHMTL(
                                    "Página de desbloqueio do SPFBL",
                                    "Ocorreu um erro no processamento desta solicitação: "
                                    + ex.getMessage() == null ? "undefined error." : ex.getMessage()
                                    );
                        }
                    } else {
                        type = "HTTPC";
                        code = 403;
                        result = "Forbidden\n";
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
                        type = "HTTPC";
                        code = 403;
                        result = "Forbidden\n";
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
            String url,
            String ip,
            String email
            ) {
        if (
                Core.hasSMTP()
                && Core.hasAdminEmail()
                && Domain.isEmail(email)
                && url != null
                && !NoReply.contains(email)
                ) {
            try {
                Server.logDebug("sending unblock by e-mail.");
                InternetAddress[] recipients = InternetAddress.parse(email);
                Properties props = System.getProperties();
                Session session = Session.getDefaultInstance(props);
                MimeMessage message = new MimeMessage(session);
                message.setHeader("Date", Core.getEmailDate());
                message.setFrom(Core.getAdminEmail());
                message.addRecipients(Message.RecipientType.TO, recipients);
                message.setSubject("Chave de desbloqueio DNSBL");
                // Corpo da mensagem.
                StringBuilder builder = new StringBuilder();
                builder.append("<html>\n");
                builder.append("  <head>\n");
                builder.append("    <meta charset=\"UTF-8\">\n");
                builder.append("    <title>Chave de desbloqueio DNSBL</title>\n");
                builder.append("  </head>\n");
                builder.append("  <body>\n");
                builder.append("       Foi solititado o desbloqueio do IP ");
                builder.append(ip);
                builder.append(" da listagem DNSBL do nosso sistema.<br>\n");
                builder.append("       Se você é o administrador deste IP e fez esta solitação,<br>\n");
                builder.append("       acesse esta URL e resolva o reCAPTCHA para finalizar o procedimento:<br>\n");
                builder.append("       <a href=\"");
                builder.append(url);
                builder.append("\">");
                builder.append(url);
                builder.append("</a><br>\n");
                builder.append("  </body>\n");
                builder.append("</html>\n");
                message.setContent(builder.toString(), "text/html;charset=UTF-8");
                message.saveChanges();
                // Enviar mensagem.
                return Core.offerMessage(message);
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        } else {
            return false;
        }
    }
    
    private static boolean enviarDesbloqueio(
            String url,
            String remetente,
            String destinatario
            ) {
        if (
                Core.hasSMTP()
                && Core.hasAdminEmail()
                && Domain.isEmail(destinatario)
                && url != null
                && !NoReply.contains(destinatario)
                ) {
            try {
                Server.logDebug("sending unblock by e-mail.");
                InternetAddress[] recipients = InternetAddress.parse(destinatario);
                Properties props = System.getProperties();
                Session session = Session.getDefaultInstance(props);
                MimeMessage message = new MimeMessage(session);
                message.setHeader("Date", Core.getEmailDate());
                message.setFrom(Core.getAdminEmail());
                message.setReplyTo(InternetAddress.parse(remetente));
                message.addRecipients(Message.RecipientType.TO, recipients);
                message.setSubject("Solicitação de envio SPFBL");
                // Corpo da mensagem.
                StringBuilder builder = new StringBuilder();
                builder.append("<html>\n");
                builder.append("  <head>\n");
                builder.append("    <meta charset=\"UTF-8\">\n");
                builder.append("    <title>Solicitação de envio</title>\n");
                builder.append("  </head>\n");
                builder.append("  <body>\n");
                builder.append("       O remetente '");
                builder.append(remetente);
                builder.append("' deseja lhe enviar mensagens\n");
                builder.append("       porém foi bloqueado pelo sistema como fonte de SPAM.<br>\n");
                builder.append("       Se você confia neste remetente e quer receber mensagens dele,\n");
                builder.append("       acesse esta URL e resolva o reCAPTCHA:<br>\n");
                builder.append("       <a href=\"");
                builder.append(url);
                builder.append("\">");
                builder.append(url);
                builder.append("</a><br>\n");
                builder.append("  </body>\n");
                builder.append("</html>\n");
                message.setContent(builder.toString(), "text/html;charset=UTF-8");
                message.saveChanges();
                // Enviar mensagem.
                return Core.offerMessage(message);
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        } else {
            return false;
        }
    }
    
    private static String getUnblockHMTL(String message) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<html>\n");
        builder.append("  <head>\n");
        builder.append("    <meta charset=\"UTF-8\">\n");
        builder.append("    <title>Página de desbloqueio do SPFBL</title>\n");
        if (Core.hasRecaptchaKeys()) {
//             novo reCAPCHA
//            builder.append("    <script src=\"https://www.google.com/recaptcha/api.js\" async defer></script>\n");
        }
        builder.append("  </head>\n");
        builder.append("  <body>\n");
        builder.append("    <form method=\"POST\">\n");
        builder.append("       A sua mensagem está sendo rejeitada por bloqueio manual.<br>\n");
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
        builder.append("       <input type=\"submit\" value=\"Liberar\">\n");
//        if (Core.hasAdminEmail()) {
//            builder.append("       Se deseja automatizar este procedimento,<br>\n");
//            builder.append("       entre em contato com <a href=\"");
//            builder.append(Core.getAdminEmail());
//            builder.append("\">");
//            builder.append(Core.getAdminEmail());
//            builder.append("</a>.<br>\n");
//        }
        builder.append("    </form>\n");
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
        if (locale.getLanguage().equals("pt")) {
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
        if (locale.getLanguage().equals("pt")) {
            builder.append("       <input type=\"submit\" value=\"Desbloquear\">\n");
        } else {
            builder.append("       <input type=\"submit\" value=\"Unblock\">\n");
        }
        builder.append("    </form>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }
    
    private static String getWhiteHMTL(String message) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<html>\n");
        builder.append("  <head>\n");
        builder.append("    <meta charset=\"UTF-8\">\n");
        builder.append("    <title>Página de desbloqueio do SPFBL</title>\n");
        if (Core.hasRecaptchaKeys()) {
//             novo reCAPCHA
//            builder.append("    <script src=\"https://www.google.com/recaptcha/api.js\" async defer></script>\n");
        }
        builder.append("  </head>\n");
        builder.append("  <body>\n");
        builder.append("    <form method=\"POST\">\n");
        builder.append("       Este remetente foi bloqueado no sistema SPFBL.<br>\n");
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
        builder.append("       <input type=\"submit\" value=\"Liberar\">\n");
//        if (Core.hasAdminEmail()) {
//            builder.append("       Se deseja automatizar este procedimento,<br>\n");
//            builder.append("       entre em contato com <a href=\"");
//            builder.append(Core.getAdminEmail());
//            builder.append("\">");
//            builder.append(Core.getAdminEmail());
//            builder.append("</a>.<br>\n");
//        }
        builder.append("    </form>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private static String getReleaseHMTL(String message) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<html>\n");
        builder.append("  <head>\n");
        builder.append("    <meta charset=\"UTF-8\">\n");
        builder.append("    <title>Página de liberação SPFBL</title>\n");
        if (Core.hasRecaptchaKeys()) {
//             novo reCAPCHA
//            builder.append("    <script src=\"https://www.google.com/recaptcha/api.js\" async defer></script>\n");
        }
        builder.append("  </head>\n");
        builder.append("  <body>\n");
        builder.append("    <form method=\"POST\">\n");
        builder.append("       O recebimento da sua mensagem está sendo atrasado por suspeita de SPAM.<br>\n");
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
        builder.append("       <input type=\"submit\" value=\"Liberar\">\n");
//        if (Core.hasAdminEmail()) {
//            builder.append("       Se deseja automatizar este procedimento,<br>\n");
//            builder.append("       entre em contato com <a href=\"");
//            builder.append(Core.getAdminEmail());
//            builder.append("\">");
//            builder.append(Core.getAdminEmail());
//            builder.append("</a>.<br>\n");
//        }
        builder.append("    </form>\n");
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private static String getMessageHMTL(String title, String message) throws ProcessException {
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
        builder.append(message.replace("\n", "<br>\n"));
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
                    hostname = Domain.normalizeHostname(hostname, false);
                    if (SPF.matchHELO(ip, hostname)) {
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
                                if (!NoReply.contains(email)) {
                                    emailSet.add(email);
                                }
                                int index = subdominio.indexOf('.', 1) + 1;
                                subdominio = subdominio.substring(index);
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
                    if (!NoReply.contains(email)) {
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
        builder.append("<html>\n");
        builder.append("  <head>\n");
        builder.append("    <meta charset=\"UTF-8\">\n");
        if (locale.getLanguage().equals("pt")) {
            builder.append("    <title>Página de checagem DNSBL</title>\n");
        } else {
            builder.append("    <title>DNSBL check page</title>\n");
        }
        builder.append("  </head>\n");
        builder.append("  <body>\n");
        builder.append("    ");
        builder.append(message);
        builder.append("<br>\n");
        builder.append("    <br>\n");
        TreeSet<String> emailSet = new TreeSet<String>();
        if (Subnet.isValidIP(query)) {
            if (locale.getLanguage().equals("pt")) {
                builder.append("    Reversos encontrados:");
            } else {
                builder.append("    rDNS found:");
            }
            Reverse reverse = Reverse.get(query, true);
            TreeSet<String> reverseSet = reverse.getAddressSet();
            if (reverseSet.isEmpty()) {
                if (locale.getLanguage().equals("pt")) {
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
                    if (SPF.matchHELO(query, hostname, true)) {
                        String domain;
                        try {
                            domain = Domain.extractDomain(hostname, false);
                        } catch (ProcessException ex) {
                            domain = null;
                        }
                        if (domain == null) {
                            if (locale.getLanguage().equals("pt")) {
                                builder.append("inválido.</li>\n");
                            } else {
                                builder.append("invalid.</li>\n");
                            }
                        } else {
                            String subdominio = hostname;
                            while (subdominio.endsWith(domain)) {
                                emailSet.add("postmaster@" + subdominio);
                                int index = subdominio.indexOf('.', 1) + 1;
                                subdominio = subdominio.substring(index);
                            }
                            if (locale.getLanguage().equals("pt")) {
                                builder.append("válido.</li>\n");
                            } else {
                                builder.append("valid.</li>\n");
                            }
                        }
                    } else {
                        if (locale.getLanguage().equals("pt")) {
                            builder.append("inválido.</li>\n");
                        } else {
                            builder.append("invalid.</li>\n");
                        }
                    }
                } while ((hostname = reverseSet.pollFirst()) != null);
                builder.append("    </ul>\n");
            }
            Distribution distribution;
            float probability;
            if (emailSet.isEmpty()) {
                if (locale.getLanguage().equals("pt")) {
                    builder.append("    Cadastre um DNS reverso válido para este IP, que aponte para o mesmo IP.<br>\n");
                } else {
                    builder.append("    Register a valid rDNS for this IP, which point to the same IP.<br>\n");
                }
            } else if ((probability = (distribution = SPF.getDistribution(query, true)).getSpamProbability(query)) > 0.01f) {
                if (distribution.isBlacklisted(query) || Block.containsIP(query)) {
                    if (locale.getLanguage().equals("pt")) {
                        builder.append("    Este IP está listado por má reputação com ");
                        builder.append(Server.PERCENT_FORMAT.format(probability));
                        builder.append(" de pontos negativos do volume total de envio.<br>\n");
                        builder.append("    <br>\n");
                        builder.append("    Para que este IP possa ser removido desta lista,<br>\n");
                        builder.append("    é necessário que o MTA de origem reduza o volume de envios para os destinatários<br>\n");
                        builder.append("    cuja rejeição SMTP tenha prefixo '5XX 5.7.1 SPFBL &lt;message&gt;'.<br>\n");
                        builder.append("    <br>\n");
                        builder.append("    Cada rejeição SMTP com este prefixo gera automaticamente um novo ponto negativo neste sistema,");
                        builder.append("    onde este ponto expira em uma semana.<br>\n");
                        builder.append("    <br>\n");
                        builder.append("    O motivo da rejeição pode ser compreendida pela mensagem que acompanha o prefixo.<br>\n");
                    } else {
                        builder.append("    This IP is listed by bad reputation in ");
                        builder.append(Server.PERCENT_FORMAT.format(probability));
                        builder.append(" of negative points of total sending.<br>\n");
                        builder.append("    <br>\n");
                        builder.append("    In order for this IP can be removed from this list,<br>\n");
                        builder.append("    it is necessary that the source MTA reduce the sending volume for the recipients<br>\n");
                        builder.append("    whose SMTP rejection has prefix '5XX 5.7.1 SPFBL &lt;message&gt;'.<br>\n");
                        builder.append("    <br>\n");
                        builder.append("    Each SMTP rejection with this prefix automatically generates a new negative point in this system,");
                        builder.append("    where this point expires in a week.<br>\n");
                        builder.append("    <br>\n");
                        builder.append("    The reason for the rejection can be understood by the message that follows the prefix.<br>\n");
                    }
                } else {
                    if (locale.getLanguage().equals("pt")) {
                        builder.append("    Este IP não está listado neste sistema porém sua reputação está com ");
                        builder.append(Server.PERCENT_FORMAT.format(probability));
                        builder.append(" de pontos negativos do volume total de envio.<br>\n");
                        builder.append("    <br>\n");
                        builder.append("    Se esta reputação tiver aumento significativo na quantidade de pontos negativos,");
                        builder.append("    este IP será automaticamente listado neste sistema.<br>\n");
                        builder.append("    <br>\n");
                        builder.append("    Para evitar que isto ocorra, reduza os envios cuja rejeição SMTP");
                        builder.append("    tenha prefixo '5XX 5.7.1 SPFBL &lt;message&gt;'.<br>\n");
                        builder.append("    <br>\n");
                        builder.append("    Cada rejeição SMTP com este prefixo");
                        builder.append("    gera automaticamente um novo ponto negativo neste sistema.<br>\n");
                        builder.append("    <br>\n");
                        builder.append("    O motivo da rejeição pode ser compreendida pela mensagem que acompanha o prefixo.<br>\n");
                    } else {
                        builder.append("    This IP is not listed in this system but its reputation is with ");
                        builder.append(Server.PERCENT_FORMAT.format(probability));
                        builder.append(" of negative points of total sending.<br>\n");
                        builder.append("    <br>\n");
                        builder.append("    If this reputation have significant increase in the number of negative points,");
                        builder.append("    this IP will automatically be listed in the system.<br>\n");
                        builder.append("    <br>\n");
                        builder.append("    To prevent this from occurring, reduce sending whose SMTP rejection");
                        builder.append("    has prefix '5XX 5.7.1 SPFBL &lt;message&gt;'.<br>\n");
                        builder.append("    <br>\n");
                        builder.append("    Each SMTP rejection with this prefix");
                        builder.append("    automatically generates a new negative point in this system.<br>\n");
                        builder.append("    <br>\n");
                        builder.append("    The reason for the rejection can be understood by the message that follows the prefix.<br>\n");
                    }
                    
                }
            } else if (Block.containsIP(query)) {
                if (locale.getLanguage().equals("pt")) {
                    builder.append("    E-mails para envio de chave de desbloqueio:");
                } else {
                    builder.append("    E-mails to send unblock key:");
                }
                builder.append("<br>\n");
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
                    if (NoReply.contains(email)) {
                        if (locale.getLanguage().equals("pt")) {
                            builder.append("não permitido.</li>\n");
                        } else {
                            builder.append("not permitted.</li>\n");
                        }
                    } else {
                        sendSet.add(email);
                        if (locale.getLanguage().equals("pt")) {
                            builder.append("permitido.</li>\n");
                        } else {
                            builder.append("permitted.</li>\n");
                        }
                    }
                } while ((email = emailSet.pollFirst()) != null);
                builder.append("    </ul>\n");
                if (sendSet.isEmpty()) {
                    if (locale.getLanguage().equals("pt")) {
                        builder.append("    Nenhum e-mail do responsável pelo IP é permitido neste sistema.<br>\n");
                    } else {
                        builder.append("    None of the responsible for IP has e-mail permitted under this system.<br>\n");
                    }
                } else {
                    builder.append("    <form method=\"POST\">\n");
                    if (locale.getLanguage().equals("pt")) {
                        builder.append("      Para que a chave de desbloqueio seja enviada,<br>\n");
                        builder.append("      selecione o endereço de e-mail do responsável pelo IP:<br>\n");
                    } else {
                        builder.append("      For the release key is sent,<br>\n");
                        builder.append("      select the responsible e-mail address of the IP:<br>\n");
                    }
                    for (String send : sendSet) {
                        builder.append("      <input type=\"checkbox\" name=\"identifier\" value=\"");
                        builder.append(send);
                        builder.append("\">");
                        builder.append(send);
                        builder.append("<br>\n");
                    }
                    if (Core.hasRecaptchaKeys()) {
                        builder.append("      <br>\n");
                        if (locale.getLanguage().equals("pt")) {
                            builder.append("      Para que sua solicitação seja aceita,<br>\n");
                            builder.append("      resolva o desafio reCAPTCHA abaixo.<br>\n");
                        } else {
                            builder.append("      For your request is accepted,<br>\n");
                            builder.append("      solve the reCAPTCHA below.<br>\n");
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
                    if (locale.getLanguage().equals("pt")) {
                        builder.append("      <input type=\"submit\" value=\"Solicitar\">\n");
                    } else {
                        builder.append("      <input type=\"submit\" value=\"Request\">\n");
                    }
                    builder.append("    </form>\n");
                }
            } else {
                if (locale.getLanguage().equals("pt")) {
                    builder.append("    Nenhum bloqueio foi encontrado para este IP.<br>\n");
                } else {
                    builder.append("    No block was found for this IP.<br>\n");
                }
            }
        } else if (Domain.isHostname(query)) {
            Distribution distribution;
            query = Domain.normalizeHostname(query, true);
            if ((distribution = SPF.getDistribution(query, true)).isNotWhitelisted(query)) {
                float probability = distribution.getSpamProbability(query);
                if (locale.getLanguage().equals("pt")) {
                    builder.append("    Este domínio está listado por má reputação com ");
                    builder.append(Server.PERCENT_FORMAT.format(probability));
                    builder.append(" de pontos negativos do volume total de envio.<br>\n");
                    builder.append("    <br>\n");
                    builder.append("    Para que este domínio possa ser removido desta lista,<br>\n");
                    builder.append("    é necessário que o MTA de origem reduza o volume de envios para os destinatários<br>\n");
                    builder.append("    cuja rejeição SMTP tenha prefixo '5XX 5.7.1 SPFBL &lt;message&gt;'.<br>\n");
                    builder.append("    <br>\n");
                    builder.append("    Cada rejeição SMTP com este prefixo gera automaticamente um novo ponto negativo neste sistema,");
                    builder.append("    onde este expira em uma semana.<br>\n");
                    builder.append("    <br>\n");
                    builder.append("    O motivo da rejeição pode ser compreendida pela mensagem que acompanha o prefixo.<br>\n");
                } else {
                    builder.append("    This domain is listed by bad reputation in ");
                    builder.append(Server.PERCENT_FORMAT.format(probability));
                    builder.append(" of negative points of total sending.<br>\n");
                    builder.append("    <br>\n");
                    builder.append("    In order for this domain can be removed from this list,<br>\n");
                    builder.append("    it is necessary that the source MTA reduce the sending volume for the recipients<br>\n");
                    builder.append("    whose SMTP rejection has prefix '5XX 5.7.1 SPFBL &lt;message&gt;'.<br>\n");
                    builder.append("    <br>\n");
                    builder.append("    Each SMTP rejection with this prefix automatically generates a new negative point in this system,");
                    builder.append("    where this point expires in a week.<br>\n");
                    builder.append("    <br>\n");
                    builder.append("    The reason for the rejection can be understood by the message that follows the prefix.<br>\n");
                }
            } else if (Block.containsHost(query)) {
                if (locale.getLanguage().equals("pt")) {
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
                if (locale.getLanguage().equals("pt")) {
                    builder.append("    Nenhum bloqueio foi encontrado para este domínio.<br>\n");
                } else {
                    builder.append("    No block was found for this domain.<br>\n");
                }
            }
        }
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private static String getComplainHMTL(
            TreeSet<String> tokenSet,
            TreeSet<String> selectionSet,
            String message,
            boolean whiteBlockForm
            ) throws ProcessException {
        StringBuilder builder = new StringBuilder();
        builder.append("<html>\n");
        builder.append("  <head>\n");
        builder.append("    <meta charset=\"UTF-8\">\n");
        builder.append("    <title>Página de denuncia SPFBL</title>\n");
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
            writeBlockFormHTML(builder, tokenSet, selectionSet);
        }
        builder.append("  </body>\n");
        builder.append("</html>\n");
        return builder.toString();
    }

    private static void writeBlockFormHTML(
            StringBuilder builder,
            TreeSet<String> tokenSet,
            TreeSet<String> selectionSet
            ) throws ProcessException {
        if (!tokenSet.isEmpty()) {
            builder.append("    <form method=\"POST\">\n");
            builder.append("      Se você deseja não receber mais mensagens desta origem no futuro,<br>\n");
            builder.append("      selecione os identificadores que devem ser bloqueados definitivamente:<br>\n");
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
                builder.append("      Para que sua solicitação seja aceita,<br>\n");
                builder.append("      resolva o desafio reCAPTCHA abaixo.<br>\n");
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
            builder.append("      <input type=\"submit\" value=\"Bloquear\">\n");
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
        Server.logInfo("listening complain on HTTP port " + PORT + ".");
    }

    @Override
    protected void close() throws Exception {
        Server.logDebug("unbinding complain HTTP on port " + PORT + "...");
        SERVER.stop(1);
        Server.logInfo("complain HTTP server closed.");
    }
}
