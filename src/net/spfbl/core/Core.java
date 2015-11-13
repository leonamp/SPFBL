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

import it.sauronsoftware.junique.AlreadyLockedException;
import it.sauronsoftware.junique.JUnique;
import it.sauronsoftware.junique.MessageHandler;
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
public class Core {
    
    private static final byte VERSION = 1;
    private static final byte SUBVERSION = 0;
    private static final byte RELEASE = 4;
    
    public static String getAplication() {
        return "SPFBL-" + getVersion();
    }
    
    public static String getVersion() {
        return VERSION + "." + SUBVERSION + "." + RELEASE;
    }
    
    private static PeerUDP peerUDP = null;
    
    public static void sendTokenToPeer(
            String token,
            String address,
            int port
            ) throws ProcessException {
        if (peerUDP != null) {
            peerUDP.send(token, address, port);
        }
    }
    
    public static String getPeerConnection() {
        return peerUDP.getConnection();
    }
    
    private static AdministrationTCP administrationTCP = null;
    private static QuerySPF querySPF = null;
    
    public static void interruptTimeout() {
        if (querySPF != null) {
            administrationTCP.interruptTimeout();
            querySPF.interruptTimeout();
        }
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
                    Core.setHostname(properties.getProperty("hostname"));
                    Core.setAdminEmail(properties.getProperty("admin_email"));
                    Core.setPortAdmin(properties.getProperty("admin_port"));
                    Core.setPortWHOIS(properties.getProperty("whois_port"));
                    Core.setPortSPFBL(properties.getProperty("spfbl_port"));
                    Core.setPortDNSBL(properties.getProperty("dnsbl_port"));
                    QueryDNSBL.setConnectionLimit(properties.getProperty("dnsbl_limit"));
                    QuerySPF.setConnectionLimit(properties.getProperty("spfbl_limit"));
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
                Core.HOSTNAME = Domain.extractHost(hostame, false);
            } else {
                Server.logError("invalid hostame '" + hostame + "'.");
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
            Core.PORT_ADMIN = (short) port;
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
            Core.PORT_WHOIS = (short) port;
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
            Core.PORT_SPFBL = (short) port;
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
            Core.PORT_DNSBL = (short) port;
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

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
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
            } else {
                startConfiguration();
                Server.logDebug("starting server...");
                Server.loadCache();
                administrationTCP = new AdministrationTCP(PORT_ADMIN);
                administrationTCP.start();
                if (PORT_WHOIS > 0) {
                    new QueryTCP(PORT_WHOIS).start();
                }
                if (PORT_SPFBL > 0) {
                    querySPF = new QuerySPF(PORT_SPFBL);
                    querySPF.start();
                    peerUDP = new PeerUDP(HOSTNAME, PORT_SPFBL, UDP_MAX);
                    peerUDP.start();
                }
                if (PORT_DNSBL > 0) {
                    new QueryDNSBL(PORT_DNSBL).start();
                }
                if (!Peer.sendHeloToAll()) {
                    Server.logDebug("the hostname '" +  HOSTNAME + "' has non global scope address.");
                }
                SPF.startTimer();
            }
        } catch (Exception ex) {
            Server.logError(ex);
            System.exit(1);
        }
    }
}
