/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package net.spfbl.core;

import net.spfbl.spf.PeerUDP;
import net.spfbl.whois.QueryTCP;
import net.spfbl.whois.QueryUDP;
import net.spfbl.spf.QuerySPF;
import java.net.InetAddress;
import net.spfbl.dnsbl.QueryDNSBL;

/**
 * Classe principal de inicilização do serviço.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Main {
    
    private static PeerUDP peerUDP;
    
    public static void sendTokenToPeer(
            String token,
            InetAddress address,
            int port
            ) throws ProcessException {
        peerUDP.send(token, address, port);
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
            Server.logDebug("Starting server...");
            int port = Integer.parseInt(args[0]);
            int size = Integer.parseInt(args[1]);
            boolean dnsbl;
            if (args.length == 3) {
                dnsbl = args[2].equals("DNSBL");
            } else {
                dnsbl = false;
            }
            Server.loadCache();
            new CommandTCP(port).start();
            new QueryTCP(port+1).start();
            new QueryUDP(port+1, size).start();
            new QuerySPF(port+2).start();
            peerUDP = new PeerUDP(port+2, size);
            peerUDP.start();
            if (dnsbl) {
                new QueryDNSBL().start();
            }
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
