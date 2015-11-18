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
    private Send send = Send.NEVER; // Status de envio para este peer.
    private Receive receive = Receive.REJECT; // Status de recebimento deste peer.
    private String email = null; // E-mail do responsável.
    private int limit = 100;
    private NormalDistribution frequency = null;
    private long last = 0; // Último recebimento.
    
    /**
     * Retém os bloqueios que necessitam de confirmação.
     */
    private TreeSet<String> retainSet = new TreeSet<String>();
    
    public enum Send {
        NEVER, // Nunca enviar bloqueios para este peer.
        DUNNO, // Obsoleto.
        ALWAYS, // Sempre enviar os bloqueios identificados.
        BLOCK, // Obsoleto.
        REPASS // Envia e repassa todos os bloqueios identificados.
    }
    
    public enum Receive {
        ACCEPT, // Aceita imediatamente os bloqueios sem repassar.
        REJECT, // Ignora todos os bloqueios recebidos.
        DROP, // Decarta todos os bloqueios recebidos e manda o firewall dropar.
        CONFIRM, // Obsoleto.
        RETAIN, // Retém todos os bloqueios recebidos para confirmação.
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
    
    public boolean setPort(int port) throws ProcessException {
        if (port < 1024 || port >= 49152) {
            throw new ProcessException("ERROR: INVALID PORT");
        } else if (this.port != port) {
            this.port = (short) port;
            CHANGED = true;
            return true;
        } else {
            return false;
        }
    }
    
    public boolean setPort(String port) throws ProcessException {
        try {
            int portInt = Integer.parseInt(port);
            return setPort(portInt);
        } catch (NumberFormatException ex) {
            throw new ProcessException("ERROR: INVALID PORT", ex);
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
    
//    public void updateLast() {
//        this.last = System.currentTimeMillis();
//    }
    
    public boolean isAlive() {
        return (System.currentTimeMillis() - last) / Server.DAY_TIME == 0;
    }
    
    public void setEmail(String email) throws ProcessException {
        if (email == null || email.length() == 0) {
            if (this.email != null) {
                this.email = null;
                CHANGED = true;
            }
        } else if (Domain.isEmail(email)) {
            if (!email.toLowerCase().equals(this.email)) {
                this.email = email.toLowerCase();
                CHANGED = true;
            }
        } else {
            throw new ProcessException("ERROR: INVALID EMAIL");
        }
    }
    
    public boolean setSendStatus(Send status) throws ProcessException {
        if (status == null) {
            throw new ProcessException("INVALID SEND");
        } else if (status == Send.BLOCK) {
            throw new ProcessException("INVALID SEND");
        } else if (status == Send.DUNNO) {
            throw new ProcessException("INVALID SEND");
        } else if (status == this.send) {
            return false;
        } else {
            this.send = status;
            CHANGED = true;
            return true;
        }
    }
    
    public boolean setSendStatus(String status) throws ProcessException {
        try {
            return setSendStatus(Send.valueOf(status));
        } catch (IllegalArgumentException ex) {
            throw new ProcessException("INVALID SEND");
        }
    }
    
    public boolean setReceiveStatus(Receive status) throws ProcessException {
        if (status == null) {
            throw new ProcessException("INVALID RECEIVE");
        } else if (status == Receive.CONFIRM) {
            throw new ProcessException("INVALID RECEIVE");
        } else if (status == this.receive) {
            return false;
        } else {
            this.receive = status;
            CHANGED = true;
            return true;
        }
    }
    
    public boolean setReceiveStatus(String status) throws ProcessException {
        try {
            return setReceiveStatus(Receive.valueOf(status));
        } catch (IllegalArgumentException ex) {
            throw new ProcessException("INVALID RECEIVE");
        }
    }
    
    public TreeSet<String> getRetationSet() {
        TreeSet<String> returnSet = new TreeSet<String>();
        returnSet.addAll(retainSet);
        return returnSet;
    }
    
    public static TreeSet<String> getAllRetationSet() {
        TreeSet<String> returnSet = new TreeSet<String>();
        for (Peer peer : Peer.getSet()) {
            for (String token : peer.getRetationSet()) {
                returnSet.add(peer.getAddress() + ':' + token);
            }
        }
        return returnSet;
    }
    
    public synchronized boolean dropExact(String token) {
        return retainSet.remove(token);
    }
    
    public String reject(String token) {
        if (dropExact(token)) {
            return "REJECTED";
        } else {
            return "NOT FOUND";
        }
    }
    
    public TreeSet<String> reject() {
        TreeSet<String> returnSet = new TreeSet<String>();
        for (String token : getRetationSet()) {
            String response = reject(token);
            if (!response.equals("NOT FOUND")) {
                returnSet.add(token + " => " + response);
            }
        }
        return returnSet;
    }
    
    public static TreeSet<String> rejectAll() {
        TreeSet<String> returnSet = new TreeSet<String>();
        for (Peer peer : Peer.getSet()) {
            for (String response : peer.reject()) {
                returnSet.add(peer.getAddress() + ':' + response);
            }
        }
        return returnSet;
    }
    
    public static TreeSet<String> rejectAll(String token) {
        TreeSet<String> returnSet = new TreeSet<String>();
        for (Peer peer : Peer.getSet()) {
            String response = peer.reject(token);
            returnSet.add(peer.getAddress() + ':' + response);
        }
        return returnSet;
    }
    
    public String release(String token) {
        if (dropExact(token)) {
            if (SPF.isIgnore(token)) {
                return "IGNORED";
            } else if (SPF.addBlockExact(token)) {
                if (isReceiveRepass()) {
                    sendToOthers(token);
                    return "REPASSED";
                } else {
                    sendToRepass(token);
                    return "ADDED";
                }
            } else {
                return "EXISTS";
            }
        } else {
            return "NOT FOUND";
        }
    }
    
    public TreeSet<String> release() {
        TreeSet<String> returnSet = new TreeSet<String>();
        for (String token : getRetationSet()) {
            String response = release(token);
            if (!response.equals("NOT FOUND")) {
                returnSet.add(token + " => " + response);
            }
        }
        return returnSet;
    }
    
    public static TreeSet<String> releaseAll() {
        TreeSet<String> returnSet = new TreeSet<String>();
        for (Peer peer : Peer.getSet()) {
            for (String response : peer.release()) {
                returnSet.add(peer.getAddress() + ':' + response);
            }
        }
        return returnSet;
    }
    
    public static TreeSet<String> releaseAll(String token) {
        TreeSet<String> returnSet = new TreeSet<String>();
        for (Peer peer : Peer.getSet()) {
            String response = peer.release(token);
            returnSet.add(peer.getAddress() + ':' + response);
        }
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
    
    public boolean drop() {
        return Peer.drop(address) != null;
    }
    
    public Peer clone(String hostname) throws ProcessException {
        Peer peerNew = create(hostname, port);
        peerNew.send = this.send;
        peerNew.receive = this.receive;
        peerNew.email = this.email;
        peerNew.limit = this.limit;
        peerNew.frequency = this.frequency.replicate();
        peerNew.last = this.last;
        return peerNew;
    }
    
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
    
    public static TreeSet<Peer> getSendAllSet() {
        TreeSet<Peer> peerSet = new TreeSet<Peer>();
        for (Peer peer : getSet()) {
            switch (peer.getSendStatus()) {
                case BLOCK:
                case ALWAYS:
                case REPASS:
                    peerSet.add(peer);
                    break;
            }
        }
        return peerSet;
    }
    
    public TreeSet<Peer> getSendSet() {
        TreeSet<Peer> peerSet = new TreeSet<Peer>();
        for (Peer peer : getSet()) {
            if (!peer.equals(this)) {
                switch (peer.getSendStatus()) {
                    case BLOCK:
                    case ALWAYS:
                    case REPASS:
                        peerSet.add(peer);
                        break;
                }
            }
        }
        return peerSet;
    }
    
    public TreeSet<Peer> getRepassSet() {
        TreeSet<Peer> peerSet = new TreeSet<Peer>();
        for (Peer peer : getSet()) {
            if (!peer.equals(this)) {
                switch (peer.getSendStatus()) {
                    case REPASS:
                        peerSet.add(peer);
                        break;
                }
            }
        }
        return peerSet;
    }
    
    public static TreeSet<Peer> dropAll() {
        TreeSet<Peer> peerSet = new TreeSet<Peer>();
        for (Peer peer : getSet()) {
            if (peer.drop()) {
                peerSet.add(peer);
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
                send(token);
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException ex) {
                // Interrompido.
            }
        }
    }
    
    public void send(String token) {
        long time = System.currentTimeMillis();
        String origin = null;
        String address = getAddress();
        String result;
        try {
            int port = getPort();
            Core.sendTokenToPeer(token, address, port);
            result = address;
        } catch (ProcessException ex) {
            result = ex.getMessage();
        }
        Server.logPeerSend(time, origin, token, result);
    }
    
    public void sendToOthers(String token) {
        String origin = null;
        for (Peer peer : getSendSet()) {
            long time = System.currentTimeMillis();
            String address = peer.getAddress();
            String result;
            try {
                int port = peer.getPort();
                Core.sendTokenToPeer(token, address, port);
                result = address;
            } catch (ProcessException ex) {
                result = ex.getMessage();
            }
            Server.logPeerSend(time, origin, token, result);
        }
    }
    
    public static void sendToAll(String token) {
        String origin = null;
        for (Peer peer : getSendAllSet()) {
            long time = System.currentTimeMillis();
            String address = peer.getAddress();
            String result;
            try {
                int port = peer.getPort();
                Core.sendTokenToPeer(token, address, port);
                result = address;
            } catch (ProcessException ex) {
                result = ex.getMessage();
            }
            Server.logPeerSend(time, origin, token, result);
        }
    }
    
    public boolean sendHELO() {
        String connection = Core.getPeerConnection();
        if (connection == null) {
            return false;
        } else {
            String origin = null;
            String email = Core.getAdminEmail();
            String helo = "HELO " + connection + (email == null ? "" : " " + email);
            long time = System.currentTimeMillis();
            String address = getAddress();
            String result = address;
            try {
                int port = getPort();
                Core.sendTokenToPeer(helo, address, port);
                result += address;
            } catch (ProcessException ex) {
                result += ex.getMessage();
            }
            Server.logQuery(time, "PEERP", origin, helo, result);
            return true;
        }
    }
    
    public static boolean sendHeloToAll() {
        String connection = Core.getPeerConnection();
        if (connection == null) {
            return false;
        } else {
            String origin = null;
            String email = Core.getAdminEmail();
            String helo = "HELO " + connection + (email == null ? "" : " " + email);
            for (Peer peer : getSendAllSet()) {
                long time = System.currentTimeMillis();
                String address = peer.getAddress();
                String result;
                try {
                    int port = peer.getPort();
                    Core.sendTokenToPeer(helo, address, port);
                    result = address;
                } catch (ProcessException ex) {
                    result = ex.getMessage();
                }
                Server.logQuery(time, "PEERP", origin, helo, result);
            }
            return true;
        }
    }
    
    public void sendToRepass(String token) {
        String origin = null;
        for (Peer peer : getRepassSet()) {
            long time = System.currentTimeMillis();
            String address = peer.getAddress();
            String result;
            try {
                int port = peer.getPort();
                Core.sendTokenToPeer(token, address, port);
                result = address;
            } catch (ProcessException ex) {
                result = ex.getMessage();
            }
            Server.logPeerSend(time, origin, token, result);
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
    
    private boolean isReceiveDrop() {
        return receive == Receive.DROP;
    }
    
    private boolean isReceiveReject() {
        return receive == Receive.REJECT;
    }
    
    private boolean isReceiveRetain() {
        return receive == Receive.RETAIN;
    }
    
    private boolean isReceiveRepass() {
        return receive == Receive.REPASS;
    }
    
    private synchronized boolean addRetain(String token) {
        return retainSet.add(token);
    }
    
    public String processReceive(String token) {
        try {
            if (!isValid(token)) {
                return "INVALID";
            } else if (Domain.isReserved(token)) {
                return "RESERVED";
            } else if (SPF.isIgnore(token)) {
                return "IGNORED";
            } else if (isReceiveReject()) {
                return "REJECTED";
            } else if (isReceiveDrop()) {
                return "DROPED";
            } else if (isReceiveRetain()) {
                if (addRetain(token)) {
                    return "RETAINED";
                } else {
                    return "DROPED";
                }
            } else if (SPF.addBlockExact(token)) {
                if (isReceiveRepass()) {
                    sendToOthers(token);
                    return "REPASSED";
                } else {
                    sendToRepass(token);
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
                            if (peer.send == Send.DUNNO) {
                                // Obsoleto.
                                peer.send = Send.NEVER;
                            } else if (peer.send == Send.BLOCK) {
                                // Obsoleto.
                                peer.send = Send.ALWAYS;
                            }
                            if (peer.receive == Receive.CONFIRM) {
                                // Obsoleto.
                                peer.receive = Receive.RETAIN;
                            }
                            if (peer.retainSet == null) {
                                peer.retainSet = new TreeSet<String>();
                            }
                            if (peer.limit == 0) {
                                peer.limit = 100;
                            }
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
    
    public boolean hasEmail() {
        return email != null;
    }
    
    public boolean hasFrequency() {
        return frequency != null;
    }
    
    public int getIdleTimeMillis() {
        if (last == 0) {
            return 0;
        } else {
            return (int) (System.currentTimeMillis() - last);
        }
    }
    
    public String getFrequencyLiteral() {
        if (hasFrequency()) {
            int frequencyInt = frequency.getMaximumInt();
            int idleTimeInt = getIdleTimeMillis();
            if (idleTimeInt > frequencyInt * 5) {
                return "DEAD";
            } else if (idleTimeInt > frequencyInt * 3) {
                return "IDLE";
            } else if (frequencyInt < limit) {
                return "<" + limit + "ms";
            } else if (frequencyInt >= 3600000) {
                return "~" + frequencyInt / 3600000 + "h";
            } else if (frequencyInt >= 60000) {
                return "~" + frequencyInt / 60000 + "min";
            } else if (frequencyInt >= 1000) {
                return "~" + frequencyInt / 1000 + "s";
            } else {
                return "~" + frequencyInt + "ms";
            }
        } else {
            return "DEAD";
        }
    }
    
    private Float getInterval() {
        long current = System.currentTimeMillis();
        Float interval;
        if (last == 0) {
            interval = null;
        } else {
            interval = (float) (current - last);
        }
        last = current;
        return interval;
    }
    
    public void addNotification() {
        Float interval = getInterval();
        if (interval == null) {
            // Se não houver intervalo definido, fazer nada.
        } else if (frequency == null) {
            frequency = new NormalDistribution(interval);
        } else {
            frequency.addElement(interval);
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
        User user = getUser();
        if (user == null) {
            return address + ":" + port
                    + (send == null ? "" : " " + send.name())
                    + (receive == null ? "" : " " + receive.name())
                    + (retainSet == null ? "" : " " + retainSet.size())
                    + " " + getFrequencyLiteral()
                    + (email == null ? "" : " <" + email + ">");
        } else {
            return address + ":" + port
                    + (send == null ? "" : " " + send.name())
                    + (receive == null ? "" : " " + receive.name())
                    + (retainSet == null ? "" : " " + retainSet.size())
                    + " " + getFrequencyLiteral()
                    + " " + user;
        }
        
    }
}
