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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import net.spfbl.core.Client;
import net.spfbl.spf.SPF;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Servidor de consulta em SPF.
 * 
 * Este serviço responde a consulta e finaliza a conexão logo em seguida.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public final class ComplainHTTP extends Server {

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
    public ComplainHTTP(String hostname, int port) throws IOException {
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
    
    @SuppressWarnings("unchecked")
    private static TreeSet<String> getIdentifierSet(HttpExchange exchange) throws IOException {
        InputStreamReader isr = new InputStreamReader(exchange.getRequestBody(), "UTF-8");
        BufferedReader br = new BufferedReader(isr);
        String query = br.readLine();
        return getIdentifierSet(query);
    }

    @SuppressWarnings("unchecked")
    private static TreeSet<String> getIdentifierSet(String query) throws UnsupportedEncodingException {
        if (query == null) {
            return null;
        } else {
            TreeSet<String> identifierSet = new TreeSet<String>();
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
                }
            }
            return identifierSet;
        }
    }
    
    private static class ComplainHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) {
            long time = System.currentTimeMillis();
            Thread.currentThread().setName("HTTPCMMND");
            String request = exchange.getRequestMethod();
            URI uri = exchange.getRequestURI();
            String command = uri.toString();
            String origin = getOrigin(exchange);
            int code;
            String result;
            String type;
            if (request.equals("POST")) {
                if (command.startsWith("/spam/")) {
                    try {
                        int index = command.indexOf('/', 1) + 1;
                        String ticket = command.substring(index);
                        String recipient = SPF.getRecipient(ticket);
                        TreeSet<String> identifierSet = getIdentifierSet(exchange);
                        if (identifierSet == null || recipient == null) {
                            type = "HTTPC";
                            code = 403;
                            result = "Forbidden\n";
                        } else {
                            TreeSet<String> tokenSet = SPF.getTokenSet(ticket);
                            for (String identifier : identifierSet) {
                                if (tokenSet.contains(identifier)) {
                                    long time2 = System.currentTimeMillis();
                                    String block = identifier + '>' + recipient;
                                    if (SPF.addBlockExact(block)) {
                                        Server.logQuery(
                                                time2, "BLOCK",
                                                origin,
                                                "BLOCK ADD " + block,
                                                "ADDED"
                                                );
                                    }
                                }
                            }
                            type = "HTTPC";
                            code = 200;
                            result = "Bloqueados: " + identifierSet + " >" + recipient + "\n";
                        }
                    } catch (Exception ex) {
                        type = "HTTPC";
                        code = 500;
                        result = ex.getMessage() + "\n";
                    }
                } else {
                    type = "HTTPC";
                    code = 403;
                    result = "Forbidden\n";
                }
            } else if (request.equals("GET") || request.equals("PUT")) {
                if (command.startsWith("/spam/")) {
                    type = "SPFSP";
                    try {
                        int index = command.indexOf('/', 1) + 1;
                        String ticket = command.substring(index);
                        TreeSet<String> complainSet = SPF.addComplain(origin, ticket);
                        if (complainSet == null) {
                            code = 404;
                            if (request.equals("PUT")) {
                                // Plain text response.
                                result = "DUPLICATE COMPLAIN\n";
                            } else {
                                result = "DUPLICATE COMPLAIN\n";
                            }
                        } else {
                            code = 200;
                            String recipient = SPF.getRecipient(ticket);
                            if (request.equals("PUT")) {
                                // Plain text response.
                                result = "OK " + complainSet + (recipient == null ? "" : " >" + recipient) + "\n";
                            } else {
                                // HTML response with block feature.
                                StringBuilder builder = new StringBuilder();
                                builder.append("<html>\n");
                                builder.append("  <head>\n");
                                builder.append("    <meta charset=\"UTF-8\">\n");
                                builder.append("    <title>Página de denuncia SPFBL</title>\n");
//                                builder.append("    <script src=\"https://www.google.com/recaptcha/api.js\" async defer></script>\n");
                                builder.append("  </head>\n");
                                builder.append("  <body>\n");
                                builder.append("    A mensagem foi denunciada com sucesso no serviço SPFBL.<br>\n");
                                builder.append("    <br>\n");
                                if (recipient != null) {
                                    TreeSet<String> tokenSet = SPF.getTokenSet(ticket);
                                    if (!tokenSet.isEmpty()) {
                                        builder.append("    <form method=\"POST\">\n");
                                        builder.append("      Se você deseja não receber mais mensagens desta origem no futuro,<br>\n");
                                        builder.append("      selecione os identificadores que devem ser bloqueados definitivamente:<br>\n");
                                        for (String identifier : SPF.getTokenSet(ticket)) {
                                            builder.append("      <input type=\"checkbox\" name=\"identifier\" value=\"");
                                            builder.append(identifier);
                                            if (Subnet.isValidIP(identifier)) {
                                                builder.append("\">");
                                            } else if (complainSet.contains(identifier)) {
                                                builder.append("\" checked>");
                                            } else {
                                                builder.append("\">");
                                            }
                                            builder.append(identifier);
                                            builder.append("<br>\n");
                                        }
                                        //                                builder.append("      <div class=\"g-recaptcha\" data-sitekey=\"${sitekey}\"></div>\n");
                                        builder.append("      <input type=\"submit\" value=\"Bloquear\">\n");
                                        builder.append("    </form>\n");
                                    }
                                }
                                builder.append("  </body>\n");
                                builder.append("</html>\n");
                                result = builder.toString();
                            }
                        }
                    } catch (Exception ex) {
                        code = 500;
                        result = ex.getMessage() + "\n";
                    }
                } else if (command.startsWith("/ham/")) {
                    type = "SPFHM";
                    try {
                        int index = command.indexOf('/', 1) + 1;
                        String ticket = command.substring(index);
                        TreeSet<String> tokenSet = SPF.deleteComplain(origin, ticket);
                        if (tokenSet == null) {
                            code = 404;
                            if (request.equals("PUT")) {
                                // Plain text response.
                                result = "ALREADY REMOVED\n";
                            } else {
                                // HTML response with whitelist feature.
                                result = "ALREADY REMOVED\n";
                            }
                        } else {
                            code = 200;
                            String recipient = SPF.getRecipient(ticket);
                            if (request.equals("PUT")) {
                                // Plain text response.
                                result = "OK " + tokenSet + (recipient == null ? "" : " >" + recipient) + "\n";
                            } else {
                                // HTML response with whitelist feature.
                                result = "OK " + tokenSet + (recipient == null ? "" : " >" + recipient) + "\n";
                            }
                        }
                    } catch (Exception ex) {
                        code = 500;
                        result = ex.getMessage() + "\n";
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
                Server.logQuery(
                        time, type,
                        origin,
                        command,
                        result);
            } catch (IOException ex) {
                Server.logError(ex);
            }
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
