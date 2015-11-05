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
package net.spfbl.core;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import net.spfbl.spf.PeerUDP;
import net.spfbl.whois.QueryTCP;
import net.spfbl.spf.QuerySPF;
import java.util.Properties;
import net.spfbl.dnsbl.QueryDNSBL;
import net.spfbl.spf.SPF;
import net.spfbl.whois.Domain;

/**
 * Classe principal de inicilização do serviço.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Main {
    
    private static PeerUDP peerUDP;
    
    public static void sendTokenToPeer(
            String token,
            String address,
            int port
            ) throws ProcessException {
        peerUDP.send(token, address, port);
    }
    
    public static String getPeerConnection() {
        return peerUDP.getConnection();
    }
    
    private static void startConfiguration() {
        File confFile = new File("spfbl.conf");
        if (confFile.exists()) {
            try {
                Properties properties = new Properties();
                FileInputStream confIS = new FileInputStream(confFile);
                try {
                    properties.load(confIS);
                    Server.setLogFolder(properties.getProperty("log_folder"));
                    Server.setLogExpires(properties.getProperty("log_expires"));
                    Main.setHostname(properties.getProperty("hostname"));
                    Main.setAdminEmail(properties.getProperty("admin_email"));
                    Main.setPortAdmin(properties.getProperty("admin_port"));
                    Main.setPortWHOIS(properties.getProperty("whois_port"));
                    Main.setPortSPFBL(properties.getProperty("spfbl_port"));
                    Main.setPortDNSBL(properties.getProperty("dnsbl_port"));
                } finally {
                    confIS.close();
                }
            } catch (IOException ex) {
                Server.logError(ex);
            }
        }
    }
    
    public static String getAdminEmail() {
        return ADMIN_EMAIL;
    }
    
    private static String HOSTNAME = "localhost";
    private static String ADMIN_EMAIL = null;
    private static short PORT_ADMIN = 9875;
    private static short PORT_WHOIS = 0;
    private static short PORT_SPFBL = 9877;
    private static short PORT_DNSBL = 0;
    private static short UDP_MAX = 512; // UDP max size packet.
    
    public static synchronized void setHostname(String hostame) {
        if (hostame != null && hostame.length() > 0) {
            if (Domain.isHostname(hostame)) {
                Main.HOSTNAME = Domain.extractHost(hostame, false);
            } else {
                Server.logError("invalid hostame '" + hostame + "'.");
            }
        }
    }
    
    public static synchronized void setAdminEmail(String email) {
        if (email != null && email.length() > 0) {
            if (Domain.isEmail(email)) {
                Main.ADMIN_EMAIL = email.toLowerCase();
            } else {
                Server.logError("invalid admin e-mail '" + email + "'.");
            }
        }
    }
    
    public static synchronized void setPortAdmin(String port) {
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
            Main.PORT_ADMIN = (short) port;
        }
    }
    
    public static synchronized void setPortWHOIS(String port) {
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
            Main.PORT_WHOIS = (short) port;
        }
    }
    
    public static synchronized void setPortSPFBL(String port) {
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
            Main.PORT_SPFBL = (short) port;
        }
    }
    
    public static synchronized void setPortDNSBL(String port) {
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
            Main.PORT_DNSBL = (short) port;
        }
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
            startConfiguration();
            Server.logDebug("Starting server...");
            Server.loadCache();
            new CommandTCP(PORT_ADMIN).start();
            if (PORT_WHOIS > 0) {
                new QueryTCP(PORT_WHOIS).start();
            }
            if (PORT_SPFBL > 0) {
                new QuerySPF(PORT_SPFBL).start();
                peerUDP = new PeerUDP(HOSTNAME, PORT_SPFBL, UDP_MAX);
                peerUDP.start();
            }
            if (PORT_DNSBL > 0) {
                new QueryDNSBL(PORT_DNSBL).start();
            }
            SPF.startTimer();
        } catch (Exception ex) {
            Server.logError(ex);
            printHelp();
            System.exit(1);
        }
    }
    
    /**
     * Imprime a ajuda.
     */
    private static void printHelp() {
        System.out.println("Starting server:");
        System.out.println("java -jar SPFBL.jar <port> <size>");
        System.out.println();
        System.out.println("Parameters:");
        System.out.println("port: port to listen commands, port+1 to listen WHOIS qeries and port+2 to listem SPFBL queries.");
        System.out.println("size: maximum packet size for result, just one packet for UDP.");
        System.out.println();
        System.out.println("Queries WHOIS:");
        System.out.println("   <host> <field1> [<field2>...]");
        System.out.println("      Query a host and return the domain fields.");
        System.out.println("   <ip> <field1> [<field2>...]");
        System.out.println("      Query an IP and return the IP block fields.");
        System.out.println("");
        System.out.println("Queries SPFBL:");
        System.out.println("   <ip> <sender> <helo>");
        System.out.println("      Query a SPF and return the qualifier and the ticket.");
        System.out.println("");
        System.out.println("Commands:");
        System.out.println("   SHUTDOWN");
        System.out.println("      Shutdown the server.");
        System.out.println("   STORE");
        System.out.println("      Store cache in disk.");
        System.out.println("   PROVIDER");
        System.out.println("      Add a e-mail provider.");
        System.out.println("   TLD");
        System.out.println("      Add a TLD.");
        System.out.println();
        System.out.println("Error messages:");
        System.out.println("   Any error message starts with 'ERROR: ' string and before comes de message.");
        System.out.println();
        System.out.println("   DOMAIN NOT FOUND");
        System.out.println("      No one domain is found to host.");
        System.out.println("   RESERVED");
        System.out.println("      The query key is a reserved TLD.");
        System.out.println("   SUBNET NOT FOUND");
        System.out.println("      No one sunbbet is found to IP.");
        System.out.println("   WAITING");
        System.out.println("      The domain is in waiting process.");
        System.out.println("   PARSING");
        System.out.println("      Fail to parse the WHOIS response.");
        System.out.println("   NSLOOKUP");
        System.out.println("      Fail to try to do a NS lookup in domain.");
        System.out.println("   SERVER NOT FOUND");
        System.out.println("      WHOIS server not found to domain or IP.");
        System.out.println("   QUERY");
        System.out.println("      Query not reconized.");
        System.out.println("   COMMAND");
        System.out.println("      Command not reconized.");
        System.out.println("   WHOIS CONNECTION FAIL");
        System.out.println("      Fail in try to connect to WHOIS service.");
        System.out.println("   WHOIS CONNECTION LIMIT");
        System.out.println("      Concurrent connection limit to WHOIS service.");
        System.out.println("   WHOIS DENIED");
        System.out.println("      Acess denied to WHOIS service.");
        System.out.println("   WHOIS QUERY LIMIT");
        System.out.println("      Query limit to WHOIS service.");
        System.out.println("   ENCODING");
        System.out.println("      WHOIS response comes not in ISO-8859-1.");
        System.out.println("   TOO MANY CONNECTIONS");
        System.out.println("      Too many simultaneous connections.");
        System.out.println("   FATAL");
        System.out.println("      A fatal error, check the LOG.");
        System.out.println();
        System.out.println("Queries and results for WHOIS in ISO-8859-1 charset.");
        System.out.println("Queries and results for SPFBL in UTF-8 charset.");
    }
}
