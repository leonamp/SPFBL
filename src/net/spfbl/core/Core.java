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
import java.net.InetAddress;
import java.net.UnknownHostException;
import net.spfbl.whois.QueryTCP;
import net.spfbl.spf.QuerySPF;
import java.util.Properties;
import java.util.Timer;
import java.util.TimerTask;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import net.spfbl.dnsbl.QueryDNSBL;
import net.spfbl.http.ComplainHTTP;
import net.spfbl.spf.SPF;
import net.spfbl.whois.Domain;
import net.spfbl.whois.SubnetIPv4;
import net.spfbl.whois.SubnetIPv6;

/**
 * Classe principal de inicilização do serviço.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Core {
    
    private static final byte VERSION = 1;
    private static final byte SUBVERSION = 2;
    private static final byte RELEASE = 3;
    
    public static String getAplication() {
        return "SPFBL-" + getVersion();
    }
    
    public static String getVersion() {
        return VERSION + "." + SUBVERSION + "." + RELEASE;
    }
    
    private static PeerUDP peerUDP = null;
    
    public static void sendCommandToPeer(
            String command,
            String address,
            int port
            ) throws ProcessException {
        if (peerUDP != null) {
            peerUDP.send(command, address, port);
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
    
    private static ComplainHTTP complainHTTP = null;
    
    public static String getSpamURL() {
        if (complainHTTP == null) {
            return null;
        } else {
            return complainHTTP.getSpamURL();
        }
    }
    
    private static AdministrationTCP administrationTCP = null;
    private static QuerySPF querySPF = null;
    
    public static void interruptTimeout() {
        if (administrationTCP != null) {
            administrationTCP.interruptTimeout();
        }
        if (querySPF != null) {
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
                    Core.setPortHTTP(properties.getProperty("http_port"));
                    Core.setMaxUDP(properties.getProperty("udp_max"));
                    PeerUDP.setConnectionLimit(properties.getProperty("peer_limit"));
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
    
    private static String HOSTNAME = null;
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
                Server.logError("invalid hostame '" + hostame + "'.");
            } else if (!isRouteable(hostame)) {
                Server.logError("unrouteable hostname '" + hostame + "'.");
            } else {
                Core.HOSTNAME = Domain.extractHost(hostame, false);
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
            } else {
                startConfiguration();
                Server.logDebug("starting server...");
                Server.loadCache();
                SPF.dropExpiredComplain();
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
                if (PORT_HTTP > 0 ) {
                    complainHTTP = new ComplainHTTP(HOSTNAME, PORT_HTTP);
                    complainHTTP.start();
                }
                Peer.sendHeloToAll();
                Core.startTimer();
            }
        } catch (Exception ex) {
            Server.logError(ex);
            System.exit(1);
        }
    }
    
    /**
     * Timer que controla os processos em background.
     */
    private static final Timer TIMER00 = new Timer("BCKGRND00");
    private static final Timer TIMER01 = new Timer("BCKGRND01");
    private static final Timer TIMER10 = new Timer("BCKGRND10");
    private static final Timer TIMER30 = new Timer("BCKGRND30");
    private static final Timer TIMER60 = new Timer("BCKGRND60");

    public static void cancelTimer() {
        TIMER00.cancel();
        TIMER01.cancel();
        TIMER10.cancel();
        TIMER30.cancel();
        TIMER60.cancel();
    }
    
    private static class TimerExpiredComplain extends TimerTask {
        public TimerExpiredComplain() {
            super();
            Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
        }
        @Override
        public void run() {
            // Verificar reclamações vencidas.
            SPF.dropExpiredComplain();
        }
    }
    
    private static class TimerInterruptTimeout extends TimerTask {
        public TimerInterruptTimeout() {
            super();
            Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
        }
        @Override
        public void run() {
            // Interromper conexões vencidas.
            Core.interruptTimeout();
        }
    }
    
    private static class TimerRefreshSPF extends TimerTask {
        public TimerRefreshSPF() {
            super();
            Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
        }
        @Override
        public void run() {
            // Atualiza registro SPF mais consultado.
            SPF.refreshSPF();
        }
    }
    
    private static class TimerRefreshHELO extends TimerTask {
        public TimerRefreshHELO() {
            super();
            Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
        }
        @Override
        public void run() {
            // Atualiza registro HELO mais consultado.
            SPF.refreshHELO();
        }
    }
    
    private static class TimerRefreshWHOIS extends TimerTask {
        public TimerRefreshWHOIS() {
            super();
            Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
        }
        @Override
        public void run() {
            // Atualiza registros WHOIS expirando.
            Server.tryRefreshWHOIS();
        }
    }
    
    private static class TimerDropExpiredSPF extends TimerTask {
        public TimerDropExpiredSPF() {
            super();
            Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
        }
        @Override
        public void run() {
            // Remoção de registros SPF expirados. 
            SPF.dropExpiredSPF();
        }
    }
    
    private static class TimerSendHeloToAll extends TimerTask {
        public TimerSendHeloToAll() {
            super();
            Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
        }
        @Override
        public void run() {
            // Envio de PING para os peers cadastrados.
            Peer.sendHeloToAll();
        }
    }
    
    private static class TimerDropExpiredPeer extends TimerTask {
        public TimerDropExpiredPeer() {
            super();
            Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
        }
        @Override
        public void run() {
            // Remoção de registros de reputação expirados. 
            Peer.dropExpired();
        }
    }
    
    private static class TimerDropExpiredHELO extends TimerTask {
        public TimerDropExpiredHELO() {
            super();
            Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
        }
        @Override
        public void run() {
            // Apagar todas os registros de DNS de HELO vencidos.
            SPF.dropExpiredHELO();
        }
    }
    
    private static class TimerDropExpiredDistribution extends TimerTask {
        public TimerDropExpiredDistribution() {
            super();
            Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
        }
        @Override
        public void run() {
            // Apagar todas as distribuições vencidas.
            SPF.dropExpiredDistribution();
        }
    }
    
    private static class TimerDropExpiredDefer extends TimerTask {
        public TimerDropExpiredDefer() {
            super();
            Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
        }
        @Override
        public void run() {
            // Apagar todas os registros de atrazo programado vencidos.
            SPF.dropExpiredDefer();
        }
    }
    
    private static class TimerStoreCache extends TimerTask {
        public TimerStoreCache() {
            super();
            Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
        }
        @Override
        public void run() {
            // Armazena todos os registros atualizados durante a consulta.
            Server.storeCache();
        }
    }
    
    private static class TimerDeleteLogExpired extends TimerTask {
        public TimerDeleteLogExpired() {
            super();
            Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
        }
        @Override
        public void run() {
            // Apaga todos os arquivos de LOG vencidos.
            Server.deleteLogExpired();
        }
    }
    
    public static void startTimer() {
        TIMER00.schedule(new TimerExpiredComplain(), 1000, 1000); // Frequência de 1 segundo.
        TIMER00.schedule(new TimerInterruptTimeout(), 1000, 1000); // Frequência de 1 segundo.
        TIMER01.schedule(new TimerRefreshSPF(), 30000, 60000); // Frequência de 1 minuto.
        TIMER01.schedule(new TimerRefreshHELO(), 60000, 60000); // Frequência de 1 minuto.
        TIMER10.schedule(new TimerRefreshWHOIS(), 600000, 600000); // Frequência de 10 minutos.
        TIMER30.schedule(new TimerDropExpiredPeer(), 900000, 1800000); // Frequência de 30 minutos.
        TIMER30.schedule(new TimerSendHeloToAll(), 1800000, 1800000); // Frequência de 30 minutos.
        TIMER60.schedule(new TimerDropExpiredSPF(), 600000, 3600000); // Frequência de 1 hora.
        TIMER60.schedule(new TimerDropExpiredHELO(), 1200000, 3600000); // Frequência de 1 hora.
        TIMER60.schedule(new TimerDropExpiredDistribution(), 1800000, 3600000); // Frequência de 1 hora.
        TIMER60.schedule(new TimerDropExpiredDefer(), 2400000, 3600000); // Frequência de 1 hora.
        TIMER60.schedule(new TimerStoreCache(), 3000000, 3600000); // Frequência de 1 hora.
        TIMER60.schedule(new TimerDeleteLogExpired(), 3600000, 3600000); // Frequência de 1 hora.
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
}
