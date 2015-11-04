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
import java.io.FileOutputStream;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.TreeMap;
import java.util.TreeSet;
import net.spfbl.spf.SPF;
import net.spfbl.spf.SPF.Distribution;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Representa um peer do sistema P2P.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public final class Peer implements Serializable, Comparable<Peer> {
    
    private static final long serialVersionUID = 1L;
    
    private final String address; // Endereço de acesso ao peer.
    private short port; // Porta de acesso ao peer.
    private Send send = Send.DUNNO; // Status de envio para este peer.
    private Receive receive = Receive.DROP; // Status de recebimento deste peer.
    private String email = null;
    
    /**
     * Guarda os bloqueios que necessitam de confirmação.
     */
    private final TreeSet<String> confirmSet = new TreeSet<String>();
    
    public enum Send {
        DUNNO, // Não envia bloqueios para este peer.
        BLOCK, // Envia todos os bloqueios identificados.
        REPASS // Envia e repassa todos os bloqueios identificados.
    }
    
    public enum Receive {
        ACCEPT, // Aceita imediatamente os bloqueios sem repassar.
        DROP, // Ignora todos os bloqueios recebidos.
        CONFIRM, // Aguarda confirmação para aceitar os bloqueios.
        REPASS // Aceita e repassa imediatamente os bloqueios.
    }
    
    private Peer(String address, int port) throws ProcessException {
        if (Domain.isHostname(address) || Subnet.isValidIP(address)) {
            this.address = Domain.extractHost(address, false);
            this.setPort(port);
        } else {
            throw new ProcessException("ERROR: INVALID PEER");
        }
    }
    
    public void setPort(int port) throws ProcessException {
        if (port >= 1024 && port < 49152) {
            this.port = (short) port;
            CHANGED = true;
        } else {
            throw new ProcessException("ERROR: INVALID PORT");
        }
    }
    
    public String getAddress() {
        return address;
    }
    
    public InetAddress getInetAddress() throws ProcessException {
        try {
            return InetAddress.getByName(address);
        } catch (UnknownHostException ex) {
            throw new ProcessException("UNKNOWN" , ex);
        }
    }
    
    public String getIP() throws ProcessException {
        InetAddress inetAddress = getInetAddress();
        String ip = inetAddress.getHostAddress();
        return Subnet.normalizeIP(ip);
    }
    
    public short getPort() {
        return port;
    }
    
    public Send getSendStatus() {
        return send;
    }
    
    public Receive getReceiveStatus() {
        return receive;
    }
    
    public String getEmail() {
        return email;
    }
    
    public User getUser() {
        return User.get(email);
    }
    
    public void setEmail(String email) throws ProcessException {
        if (email == null || email.length() == 0) {
            this.email = null;
        } else if (Domain.isEmail(email)) {
            this.email = email.toLowerCase();
            CHANGED = true;
        } else {
            throw new ProcessException("ERROR: INVALID EMAIL");
        }
    }
    
    public boolean setSendStatus(String status) throws ProcessException {
        try {
            Send sendNew =  Send.valueOf(status);
            if (sendNew == this.send) {
                return false;
            } else {
                this.send = sendNew;
                CHANGED = true;
                return true;
            }
        } catch (IllegalArgumentException ex) {
            throw new ProcessException("INVALID SEND");
        }
    }
    
    public boolean setReceiveStatus(String status) throws ProcessException {
        try {
            Receive receiveNew =  Receive.valueOf(status);
            if (receiveNew == this.receive) {
                return false;
            } else {
                this.receive = Receive.valueOf(status);
                CHANGED = true;
                return true;
            }
            
        } catch (IllegalArgumentException ex) {
            throw new ProcessException("INVALID RECEIVE");
        }
    }
    
    public TreeSet<String> getConfirmSet() {
        TreeSet<String> returnSet = new TreeSet<String>();
        returnSet.addAll(confirmSet);
        return returnSet;
    }
    
    /**
     * Mapa de usuário com busca de hash O(1).
     */
    private static final HashMap<String,Peer> MAP = new HashMap<String,Peer>();
    
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean CHANGED = false;
    
    public synchronized static Peer create(
            String hostname, String port
            ) throws ProcessException {
        try {
            int portInt = Integer.parseInt(port);
            return create(hostname, portInt);
        } catch (NumberFormatException ex) {
            throw new ProcessException("ERROR: INVALID PORT", ex);
        }
    }
    
    public synchronized static Peer create(
            String hostname, int port
            ) throws ProcessException {
        hostname = Domain.extractHost(hostname, false);
        if (MAP.containsKey(hostname)) {
            return null;
        } else {
            Peer peer = new Peer(hostname, port);
            MAP.put(hostname, peer);
            CHANGED = true;
            return peer;
        }
    }
    
    public synchronized static TreeSet<Peer> getSet() {
        TreeSet<Peer> peerSet = new TreeSet<Peer>();
        peerSet.addAll(MAP.values());
        return peerSet;
    }
    
    public synchronized static TreeSet<Peer> getSendSet() {
        TreeSet<Peer> peerSet = new TreeSet<Peer>();
        for (Peer peer : MAP.values()) {
            switch (peer.getSendStatus()) {
                case BLOCK:
                case REPASS:
                    peerSet.add(peer);
                    break;
            }
        }
        return peerSet;
    }
    
    public synchronized static Peer drop(String address) {
        Peer peer = MAP.remove(address);
        if (peer != null) {
            CHANGED = true;
        }
        return peer;
    }
    
    public synchronized static Peer get(String address) {
        if (address == null) {
            return null;
        } else {
            return MAP.get(address);
        }
    }
    
    public static Peer get(InetAddress inetAddress) throws ProcessException {
        String ip = inetAddress.getHostAddress();
        ip = Subnet.normalizeIP(ip);
        for (Peer peer : getSet()) {
            if (ip.equals(peer.getIP())) {
                return peer;
            }
        }
        return null;
    }
    
    public static synchronized HashMap<String,Peer> getMap() {
        HashMap<String,Peer> map = new HashMap<String,Peer>();
        map.putAll(MAP);
        return map;
    }
    
    public void sendAll() {
        TreeMap<String,Distribution> distributionSet = SPF.getDistributionMap();
        for (String token : distributionSet.keySet()) {
            Distribution distribution = distributionSet.get(token);
            if (distribution.isBlocked(token)) {
                long time = System.currentTimeMillis();
                String address = getAddress();
                String result;
                try {
                    int port = getPort();
                    Main.sendTokenToPeer(token, address, port);
                    result = "SENT";
                } catch (ProcessException ex) {
                    result = ex.toString();
                }
                Server.logPeerSend(time, address, token, result);
            }
        }
    }
    
    public static void sendToAll(String token) {
        for (Peer peer : getSendSet()) {
            long time = System.currentTimeMillis();
            String address = peer.getAddress();
            String result;
            try {
                int port = peer.getPort();
                Main.sendTokenToPeer(token, address, port);
                result = "SENT";
            } catch (ProcessException ex) {
                result = ex.getMessage();
            }
            Server.logPeerSend(time, address, token, result);
        }
    }
    
    private static boolean isValid(String token) {
        if (token == null || token.length() == 0) {
            return false;
        } else if (Subnet.isValidIP(token)) {
            return false;
        } else if (token.startsWith(".") && Domain.isHostname(token.substring(1))) {
            return true;
        } else if (token.contains("@") && Domain.isEmail(token)) {
            return true;
        } else if (token.startsWith("@") && Domain.containsDomain(token.substring(1))) {
            return true;
        } else {
            return false;
        }
    }
    
    private boolean isDrop() {
        return receive == Receive.DROP;
    }
    
    private boolean isConfirm() {
        return receive == Receive.CONFIRM;
    }
    
    private boolean isRepass() {
        return receive == Receive.REPASS;
    }
    
    private synchronized boolean addConfirm(String token) {
        return confirmSet.add(token);
    }
    
    public String processReceive(String token) {
        try {
            if (!isValid(token)) {
                return "INVALID";
            } else if (SPF.isIgnore(token)) {
                return "IGNORED";
            } else if (isDrop()) {
                return "DROPED";
            } else if (isConfirm()) {
                if (addConfirm(token)) {
                    return "GUARDED";
                } else {
                    return "DROPED";
                }
            } else if (SPF.addBlockExact(token)) {
                if (isRepass()) {
                    sendToAll(token);
                    return "REPASSED";
                } else {
                    return "ADDED";
                }
            } else {
                return "EXISTS";
            }
        } catch (Exception ex) {
            Server.logError(ex);
            return ex.getMessage();
        }
    }
    
    public static void store() {
        if (CHANGED) {
            try {
                long time = System.currentTimeMillis();
                HashMap<String,Peer> map = getMap();
                File file = new File("./data/peer.map");
                FileOutputStream outputStream = new FileOutputStream(file);
                try {
                    SerializationUtils.serialize(map, outputStream);
                    // Atualiza flag de atualização.
                    CHANGED = false;
                } finally {
                    outputStream.close();
                }
                Server.logStore(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    public static synchronized void load() {
        long time = System.currentTimeMillis();
        File file = new File("./data/peer.map");
        if (file.exists()) {
            try {
                HashMap<Object,Object> map;
                FileInputStream fileInputStream = new FileInputStream(file);
                try {
                    map = SerializationUtils.deserialize(fileInputStream);
                } finally {
                    fileInputStream.close();
                }
                for (Object key : map.keySet()) {
                    Object value = map.get(key);
                    if (key instanceof InetAddress) {
                        InetAddress address = (InetAddress) key;
                        Integer port = (Integer) value;
                        create(address.getHostAddress(), port);
                    } else if (key instanceof String) {
                        String address = (String) key;
                        if (value instanceof Integer) {
                            Integer port = (Integer) value;
                            create(address, port);
                        } else if (value instanceof Peer) {
                            Peer peer = (Peer) value;
                            MAP.put(address, peer);
                        }
                    }
                }
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    @Override
    public int hashCode() {
        return address.hashCode();
    }
    
    @Override
    public boolean equals(Object o) {
        if (o instanceof Peer) {
            Peer other = (Peer) o;
            return this.address.equals(other.address);
        } else {
            return false;
        }
    }
    
    @Override
    public int compareTo(Peer other) {
        if (other == null) {
            return -1;
        } else {
            return this.toString().compareTo(other.toString());
        }
    }
    
    @Override
    public String toString() {
        return address + ":" + port
                + " " + send.name()
                + " " + receive.name()
                + " " + confirmSet.size()
                + (email == null ? "" : "<" + email + ">");
    }
}
