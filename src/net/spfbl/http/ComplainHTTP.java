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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import net.spfbl.core.Server;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.TreeSet;
import net.spfbl.core.Client;
import net.spfbl.core.ProcessException;
import net.spfbl.spf.SPF;

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
    
    private static class ComplainHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            long time = System.currentTimeMillis();
            Thread.currentThread().setName("HTTPCMMND");
            String request = exchange.getRequestMethod();
            URI uri = exchange.getRequestURI();
            String command = uri.toASCIIString();
            String origin = getOrigin(exchange);
            int code;
            String result;
            String type;
            if (request.equals("GET")) {
                if (command.startsWith("/spam/")) {
                    type = "SPFSP";
                    try {
                        int index = command.indexOf('/', 1) + 1;
                        String ticket = command.substring(index);
                        TreeSet<String> tokenSet = SPF.addComplain(origin, ticket);
                        if (tokenSet == null) {
                            code = 404;
                            result = "DUPLICATE COMPLAIN\n";
                        } else {
                            code = 200;
                            result = "OK " + tokenSet + "\n";
                        }
                    } catch (ProcessException ex) {
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
                            result = "ALREADY REMOVED\n";
                        } else {
                            code = 200;
                            result = "OK " + tokenSet + "\n";
                        }
                    } catch (ProcessException ex) {
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
            response(code, result, exchange);
            command = request + " " + command;
            result = code + " " + result;
            Server.logQuery(
                    time, type,
                    origin,
                    command,
                    result
                    );
        }
    }
    
    private static void response(int code, String response,
            HttpExchange exchange) throws IOException {
        exchange.sendResponseHeaders(code, response.length());
        OutputStream os = exchange.getResponseBody();
        try {
            os.write(response.getBytes("UTF-8"));
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
