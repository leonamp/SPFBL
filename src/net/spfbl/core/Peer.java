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

import net.spfbl.data.Block;
import net.spfbl.data.Ignore;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.Serializable;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.TreeSet;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import net.spfbl.data.Generic;
import net.spfbl.spf.SPF;
import net.spfbl.spf.SPF.Distribution;
import net.spfbl.spf.SPF.Status;
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
    private short ports = 0; // Porta secura de acesso ao peer.
    private short https = 0; // Porta secura para validação do peer.
    private SecretKey encryptKey = null;
    private SecretKey decryptKey = null;
    private Send send = Send.REPUTATION; // Status de envio para este peer.
    private Receive receive = Receive.DROP; // Status de recebimento deste peer.
    private String email = null; // E-mail do responsável.
    private int limit = 100;
    private NormalDistribution frequency = null;
    private long last = 0; // Último recebimento.
    private long create = System.currentTimeMillis(); // Data de criação.
    
    /**
     * Versão do peer.
     */
    private byte version = 0;
    private byte subversion = 0;
    
    /**
     * Tabela de reputação do peer.
     */
    private final HashMap<String,Binomial> reputationMap = null;
    private TreeMap<String,Binomial> reputationMap2 = new TreeMap<>();
    private TreeMap<String,NormalDistribution> frequencyMap = new TreeMap<>();
    private short reputationMax = 0;
    
    private Peer(Peer other) {
        this.address = other.address;
        this.port = other.port;
        this.ports = other.ports;
        this.https = other.https;
        this.encryptKey = other.encryptKey;
        this.decryptKey = other.decryptKey;
        this.version = other.version;
        this.subversion = other.subversion;
        this.send = other.send;
        this.receive = other.receive;
        this.email = other.email;
        this.limit = other.limit;
        if (other.frequency == null) {
            this.frequency = null;
        } else {
            this.frequency = other.frequency.replicate();
        }
        this.last = other.last;
        this.create = other.create;
        this.reputationMap2.putAll(other.getReputationMap());
        this.reputationMax = other.reputationMax;
    }

    public enum Send {
        NEVER, // Nunca enviar bloqueios e tabela de reputação para este peer.
        DUNNO, // Obsoleto.
        REPUTATION, // Sempre enviar somente a tabela de reputação.
        ALWAYS, // Sempre enviar os bloqueios e tabela de reputação.
        BLOCK, // Obsoleto.
        REPASS, // Envia e repassa todos os bloqueios recebidos.
        MIRROR // Trata o peer como espelho no envio.
    }
    
    public enum Receive {
        ACCEPT, // Aceita imediatamente os bloqueios sem repassar.
        REJECT, // Ignora todos os bloqueios e reputação recebidos.
        DROP, // Decarta todos os bloqueios recebidos e manda o firewall dropar.
        CONFIRM, // Obsoleto.
        REPUTATION, // Aceitar somente tabela de reputação.
        RETAIN, // Obsoleto.
        REPASS, // Aceita e repassa imediatamente os bloqueios.
        MIRROR // Trata o peer como espelho no recebimento.
     }
    
    private Peer(String address, int port, int ports, int https) throws ProcessException {
        if (Domain.isHostname(address) || Subnet.isValidIP(address)) {
            this.address = Domain.extractHost(address, false);
            this.setPort(port);
            this.setSecuredPort(ports, https);
        } else {
            throw new ProcessException("INVALID PEER");
        }
    }
    
    public boolean setPort(int port) throws ProcessException {
        if (port < 1024 || port >= 49152) {
            throw new ProcessException("INVALID PORT");
        } else if (this.port != port) {
            this.port = (short) port;
            return CHANGED = true;
        } else {
            return false;
        }
    }
    
    public boolean setPort(String port) throws ProcessException {
        try {
            int portInt = Integer.parseInt(port);
            return setPort(portInt);
        } catch (NumberFormatException ex) {
            throw new ProcessException("INVALID PORT", ex);
        }
    }
    
    public boolean setSecuredPort(int port, int https) throws ProcessException {
        if (port != 0 && (port < 1024 || port >= 49152)) {
            throw new ProcessException("INVALID P2P PORT");
        } else if (https != 0 && https != 443 && (port < 1024 || port >= 49152)) {
            throw new ProcessException("INVALID HTTPS PORT");
        }
        if (port == 0) {
            https = 0;
        } else if (https == 0) {
            https = 443;
        }
        if (this.ports != port || this.https != https) {
            this.ports = (short) port;
            this.https = (short) https;
            return CHANGED = true;
        } else {
            return false;
        }
    }
    
    public boolean setSecuredPort(String port, String https) throws ProcessException {
        if (port == null || port.length() == 0) {
            port = "0";
            https = "0";
        } else if (https == null || https.length() == 0) {
            https = "443";
        }
        int portInt;
        int httpsInt;
        try {
            portInt = Integer.parseInt(port);
        } catch (NumberFormatException ex) {
            throw new ProcessException("INVALID P2P PORT", ex);
        }
        try {
            httpsInt = Integer.parseInt(https);
        } catch (NumberFormatException ex) {
            throw new ProcessException("INVALID HTTPS PORT", ex);
        }
        return setSecuredPort(portInt, httpsInt);
    }
    
    public String getAddress() {
        return address;
    }
    
    public String getAddressHTTPS() {
        if (https == 0) {
            return null;
        } else if (https == 443) {
            return address;
        } else {
            return address + ":" + https;
        }
    }
    
    public double getCorrelacao() {
        ArrayList<Float> xList = new ArrayList<>();
        ArrayList<Float> yList = new ArrayList<>();
        float xSum = 0;
        float ySum = 0;
        int n = 0;
        for (String token : getReputationKeySet()) {
            Binomial binomial = getReputation(token);
            if (binomial != null && binomial.getTotalSize() > 7) {
                Distribution distribution = SPF.getDistribution(token);
                if (distribution != null && distribution.getTotalSize() > 7) {
                    float x = binomial.getSpamProbability();
                    float y = distribution.getSpamProbability();
                    xSum += x;
                    ySum += y;
                    xList.add(x);
                    yList.add(y);
                    n++;
                }
            }
        }
        if (n > 32) {
            double xAvg = (double) xSum / n;
            double yAvg = (double) ySum / n;
            double coVar = 0.0d;
            xSum = 0;
            ySum = 0;
            for (int i = 0; i < n; i++) {
                float x = xList.get(i);
                float y = yList.get(i);
                coVar += (x - xAvg) * (y - yAvg);
                xSum += (x - xAvg) * (x - xAvg);
                ySum += (y - yAvg) * (y - yAvg);
            }
            return coVar / Math.sqrt(xSum * ySum);
        } else {
            return 0.0d;
        }
    }
    
    public InetAddress getInetAddress() throws UnknownHostException {
        return InetAddress.getByName(address);
    }
    
    public String getIP() throws UnknownHostException {
        InetAddress inetAddress = getInetAddress();
        String ip = inetAddress.getHostAddress();
        return Subnet.normalizeIP(ip);
    }
    
    public short getPort() {
        return port;
    }
    
    public short getSecuredPort() {
        return ports;
    }
        
    public synchronized SecretKey getEncryptKey() {
        return encryptKey;
    }
    
    public synchronized SecretKey getDecryptKey() {
        return decryptKey;
    }
    
    public synchronized String newDecryptKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(new SecureRandom());
            SecretKey secretKey = keyGen.generateKey();
            String result = Core.BASE64.encodeAsString(secretKey.getEncoded());
            decryptKey = secretKey;
            Server.logTrace("new decrypt key for " + getAddress() + ": " + result);
            return result;
        } catch (Exception ex) {
            decryptKey = null;
            Server.logError(ex);
            return null;
        }
    }
    
    public synchronized boolean requestSecretKey(String hostname) {
        String addressHTTPS = getAddressHTTPS();
        if (addressHTTPS == null) {
            return false;
        } else if (getSendStatus() == Send.NEVER) {
            return false;
        } else {
            KeyStore keyStore = Core.loadKeyStore(hostname);
            if (keyStore == null) {
                return false;
            } else {
                try {
                    KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                    kmf.init(keyStore, hostname.toCharArray());
                    KeyManager[] km = kmf.getKeyManagers();
                    TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
                    tmf.init(keyStore);
                    TrustManager[] tm = tmf.getTrustManagers();
                    SSLContext sslContext = SSLContext.getInstance("TLS");
                    sslContext.init(km, tm, null);
                    SSLSocketFactory socketFactory = sslContext.getSocketFactory();

                    URL url = new URL("https://" + addressHTTPS + "/.well-known/secret-key/" + hostname);
                    HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
                    conn.setSSLSocketFactory(socketFactory);
                    conn.connect();
                    try {
                        int responseCode = conn.getResponseCode();
                        if (responseCode == HttpURLConnection.HTTP_OK) {
                            StringBuilder builder = new StringBuilder();
                            try (InputStream inputStream = conn.getInputStream()) {
                                int code;
                                while ((code = inputStream.read()) != -1) {
                                    builder.append((char) code);
                                }
                            }
                            byte[] encodedKey = Core.BASE64.decode(builder.toString());
                            encryptKey = new SecretKeySpec(encodedKey, "AES");
                            Server.logTrace("new encrypt key for " + getAddress() + ": " + builder);
                            return true;
                        } else {
                            encryptKey = null;
                            return false;
                        }
                    } finally {
                        conn.disconnect();
                    }
                } catch (Exception ex) {
                    Server.logError(ex);
                    encryptKey = null;
                    return false;
                }
            }
        }
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
    
    public String getVersion() {
        if (version == 0) {
            return null;
        } else {
            return version + "." + subversion;
        }
    }
    
    public boolean isCompatible(int version, int subversion) {
        if (this.version > version) {
            return true;
        } else if (this.version < version) {
            return false;
        } else  {
            return this.subversion >= subversion;
        }
    }
    
    public User getUser() {
        return User.get(email);
    }
    
    public boolean isAlive() {
        return (System.currentTimeMillis() - last) / Server.DAY_TIME == 0;
    }
    
    public void setEmail(String email) throws ProcessException {
        if (email == null || email.length() == 0) {
            if (this.email != null) {
                this.email = null;
                CHANGED = true;
            }
        } else if (Domain.isValidEmail(email)) {
            if (!email.toLowerCase().equals(this.email)) {
                this.email = email.toLowerCase();
                CHANGED = true;
            }
        } else {
            throw new ProcessException("INVALID EMAIL");
        }
    }
    
    public boolean setVersion(String token) throws ProcessException {
        if (token == null || token.length() == 0) {
            return false;
        } else {
            StringTokenizer tokenizer = new StringTokenizer(token, ".");
            if (tokenizer.countTokens() >= 2) {
                try {
                    byte versionNew = Byte.valueOf(tokenizer.nextToken());
                    byte subversionNew = Byte.valueOf(tokenizer.nextToken());
                    if (this.version != versionNew || this.subversion != subversionNew) {
                        this.version = versionNew;
                        this.subversion = subversionNew;
                        return CHANGED = true;
                    } else {
                        return false;
                    }
                } catch (NumberFormatException ex) {
                    throw new ProcessException("INVALID VERSION");
                }
            } else {
                throw new ProcessException("INVALID VERSION");
            }
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
    
    public synchronized TreeSet<String> getReputationKeySet() {
        TreeSet<String> keySet = new TreeSet<>();
        if (reputationMap2 != null) {
            keySet.addAll(reputationMap2.keySet());
        }
        return keySet;
    }
    
    public TreeMap<String,Binomial> getReputationMap() {
        TreeMap<String,Binomial> returnSet = new TreeMap<>();
        for (String key : getReputationKeySet()) {
            Binomial binomial = getReputation(key);
            if (binomial != null) {
                returnSet.put(key, binomial);
            }
        }
        return returnSet;
    }
    
    public static TreeSet<String> getReputationKeyAllSet() {
        TreeSet<String> keySet = new TreeSet<>();
        for (Peer peer : Peer.getSet()) {
            keySet.addAll(peer.getReputationKeySet());
        }
        return keySet;
    }
    
    /**
     * Mapa de usuário com busca de hash O(1).
     */
    private static final HashMap<String,Peer> MAP = new HashMap<>();
    
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean CHANGED = false;
    
    public boolean drop() {
        return Peer.drop(address) != null;
    }
    
    public Peer clone(String hostname) throws ProcessException {
        Peer peerNew = create(hostname, port, ports, https);
        peerNew.encryptKey = this.encryptKey;
        peerNew.decryptKey = this.decryptKey;
        peerNew.version = this.version;
        peerNew.subversion = this.subversion;
        peerNew.send = this.send;
        peerNew.receive = this.receive;
        peerNew.email = this.email;
        peerNew.limit = this.limit;
        peerNew.frequency = this.frequency.replicate();
        peerNew.last = this.last;
        peerNew.create = this.create;
        return peerNew;
    }
    
    public static Peer create(
            String hostname, String port, String ports, String https
            ) throws ProcessException {
        try {
            int portInt = Integer.parseInt(port);
            int portsInt = ports == null ? 0 : Integer.parseInt(ports);
            int httpsInt = https == null ? 0 : Integer.parseInt(https);
            return create(hostname, portInt, portsInt, httpsInt);
        } catch (NumberFormatException ex) {
            throw new ProcessException("INVALID PORT", ex);
        }
    }
    
    public synchronized static Peer create(
            String hostname, int port, int ports, int https
            ) throws ProcessException {
        hostname = Domain.extractHost(hostname, false);
        if (MAP.containsKey(hostname)) {
            return null;
        } else {
            Peer peer = new Peer(hostname, port, ports, https);
            MAP.put(hostname, peer);
            CHANGED = true;
            return peer;
        }
    }
    
    public synchronized static TreeSet<Peer> getSet() {
        TreeSet<Peer> peerSet = new TreeSet<>();
        peerSet.addAll(MAP.values());
        return peerSet;
    }
    
    public static TreeSet<Peer> getSendAllSet() {
        TreeSet<Peer> peerSet = new TreeSet<>();
        for (Peer peer : getSet()) {
            switch (peer.getSendStatus()) {
                case REPUTATION:
                case BLOCK:
                case ALWAYS:
                case REPASS:
                    peerSet.add(peer);
                    break;
            }
        }
        return peerSet;
    }
    
    public static TreeSet<Peer> getReputationSet() {
        TreeSet<Peer> peerSet = new TreeSet<>();
        for (Peer peer : getSet()) {
            switch (peer.getSendStatus()) {
                case BLOCK:
                case REPUTATION:
                case ALWAYS:
                case REPASS:
                case MIRROR:
                    peerSet.add(peer);
                    break;
            }
        }
        return peerSet;
    }
    
    public TreeSet<Peer> getSendSet() {
        TreeSet<Peer> peerSet = new TreeSet<>();
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
        TreeSet<Peer> peerSet = new TreeSet<>();
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
    
    public static TreeSet<Peer> getMirrorSet() {
        TreeSet<Peer> peerSet = new TreeSet<>();
        for (Peer peer : getSet()) {
            if (peer.getSendStatus() == Send.MIRROR) {
                peerSet.add(peer);
            }
        }
        return peerSet;
    }
    
    public static TreeSet<Peer> dropAll() {
        TreeSet<Peer> peerSet = new TreeSet<>();
        for (Peer peer : getSet()) {
            if (peer.drop()) {
                peerSet.add(peer);
            }
        }
        return peerSet;
    }
    
    public static Peer drop(String address) {
        Peer peer = MAP.remove(address);
        if (peer != null) {
            CHANGED = true;
        }
        return peer;
    }
    
    public static Peer get(String address) {
        if (address == null) {
            return null;
        } else {
            return MAP.get(address);
        }
    }
    
    public boolean isAddress(InetAddress inetAddress) {
        String ip = inetAddress.getHostAddress();
        return SPF.matchHELO(ip, getAddress());
    }
    
    public static Peer get(InetAddress inetAddress) {
        String ip = inetAddress.getHostAddress();
        ip = Subnet.normalizeIP(ip);
        for (Peer peer : getSet()) {
            if (SPF.matchHELO(ip, peer.getAddress())) {
                return peer;
            }
        }
        return null;
    }
    
    public static boolean has(InetAddress inetAddress) {
        String ip = inetAddress.getHostAddress();
        ip = Subnet.normalizeIP(ip);
        for (Peer peer : getSet()) {
            if (SPF.matchHELO(ip, peer.getAddress())) {
                return true;
            }
        }
        return false;
    }
    
    public static HashMap<String,Peer> getMap() {
        HashMap<String,Peer> map = new HashMap<>();
        for (Peer peer : getSet()) {
            Peer clone = new Peer(peer);
            map.put(clone.getAddress(), clone);
        }
        return map;
    }
    
//    public void send(String token) {
//        if (Core.hasPeerConnection()) {
//            long time = System.currentTimeMillis();
//            String origin = null;
//            String address = getAddress();
//            int port = getPort();
//            int ports = 0;
//            SecretKey key = null;
//            if (isCompatible(2, 8)) {
//                ports = getSecuredPort();
//                key = getEncryptKey();
//            }
//            String result = Core.sendCommandToPeer(
//                    token, address, port, ports, key
//            );
//            Server.logPeerSend(time, origin, token, result);
//        }
//    }
    
    public void sendToOthers(String token) {
        long time = System.currentTimeMillis();
        if (Core.hasPeerConnection()) {
            String origin = null;
            String result = "SENT";
            try {
                for (Peer peer : getSendSet()) {
                    String address = peer.getAddress();
                    int port = peer.getPort();
                    int ports = 0;
                    SecretKey key = null;
                    if (peer.isCompatible(2, 8)) {
                        ports = peer.getSecuredPort();
                        key = peer.getEncryptKey();
                    }
                    Core.sendCommandToPeer(
                            token, address,
                            port, ports, key
                    );
                }
            } catch (Exception ex) {
                result = ex.getMessage();
            }
            Server.logPeerSend(time, origin, token, result);
        }
    }
    
//    public static void sendToAll(String token) {
//        long time = System.currentTimeMillis();
//        if (Core.hasPeerConnection()) {
//            String origin = null;
//            String result = "SENT";
//            try {
//                for (Peer peer : getSendAllSet()) {
//                    String address = peer.getAddress();
//                    int port = peer.getPort();
//                    int ports = 0;
//                    SecretKey key = null;
//                    if (peer.isCompatible(2, 8)) {
//                        ports = peer.getSecuredPort();
//                        key = peer.getEncryptKey();
//                    }
//                    Core.sendCommandToPeer(
//                            token, address,
//                            port, ports, key
//                    );
//                }
//            } catch (Exception ex) {
//                result = ex.getMessage();
//            }
//            Server.logPeerSend(time, origin, token, result);
//        }
//    }
    
    public static void sendBlockToAll(String token) {
        if (isValidBlock(token)) {
            long time = System.currentTimeMillis();
            if (Core.hasPeerConnection()) {
                String origin = null;
                String result = "SENT";
                String command = "BLOCK " + token;
                try {
                    for (Peer peer : getSendAllSet()) {
                        String address = peer.getAddress();
                        int port = peer.getPort();
                        int ports = 0;
                        SecretKey key = null;
                        if (peer.isCompatible(2, 8)) {
                            ports = peer.getSecuredPort();
                            key = peer.getEncryptKey();
                        }
                        Core.sendCommandToPeer(
                                command, address,
                                port, ports, key
                        );
                    }
                } catch (Exception ex) {
                    result = ex.getMessage();
                }
                Server.logPeerSend(time, origin, command, result);
            }
        }
    }
    
    /**
     * Método de transição.
     * @param token
     * @param distribuiton 
     */
    public static void sendToAll(String token, Distribution distribuiton) {
        if (SPF.isValidReputation(token)) {
            long time = System.currentTimeMillis();
            if (Core.hasPeerConnection()) {
                int[] binomial;
                Float[] frequency;
                if (distribuiton == null) {
                    binomial = new int[2];
                    frequency = null;
                } else {
                    binomial = distribuiton.getBinomial();
                    frequency = distribuiton.getFrequencyXiSum();
                }
                int ham = binomial[0];
                int spam = binomial[1];
                if (spam % 3 == 0) {
                    String origin = null;
                    String result = null;
                    String commandShort = "REPUTATION " + token + " " + ham + " " + spam;
                    String commandLong = null;
                    if (Core.isTooBigForPeers(commandShort)) {
                        result = "TOO BIG";
                    } else if (frequency == null) {
                        commandLong = commandShort;
                    } else if (ham + spam == 0) {
                        commandLong = commandShort;
                    } else {
                        commandLong = commandShort + " " + frequency[0] + " " + frequency[1];
                        if (Core.isTooBigForPeers(commandLong)) {
                            commandLong = commandShort;
                        }
                    }
                    if (result == null) {
                        try {
                            result = "NO PEERS";
                            for (Peer peer : getReputationSet()) {
                                String address = peer.getAddress();
                                int port = peer.getPort();
                                int ports = 0;
                                SecretKey key = null;
                                if (peer.isCompatible(2, 8)) {
                                    ports = peer.getSecuredPort();
                                    key = peer.getEncryptKey();
                                }
                                Core.sendCommandToPeer(
                                        commandLong, address,
                                        port, ports, key
                                );
                                result = "SENT";
                            }
                        } catch (Exception ex) {
                            result = ex.getMessage();
                        }
                    }
                    Server.logPeerSend(time, origin, commandShort, result);
                }
            }
        }
    }
    
    public boolean sendHELO() {
        String connection = Core.getPeerConnection();
        if (connection == null) {
            return false;
        } else {
            String origin = null;
            String emailLocal = Core.getAdminEmail();
            String connectionSecured = Core.getPeerSecuredConnection();
            String helo;
            if (connectionSecured != null && isCompatible(2, 8)) {
                helo = "HELO " + connectionSecured + " " + Core.getSubVersion() + (emailLocal == null ? "" : " " + emailLocal);
            } else {
                helo = "HELO " + connection + (emailLocal == null ? "" : " " + emailLocal);
            }
            long time = System.currentTimeMillis();
            String addressLocal = getAddress();
            int port = getPort();
            int ports = 0;
            SecretKey key = null;
            String result = Core.sendCommandToPeer(
                    helo, addressLocal,
                    port, ports, key
            );
            Server.log(time, Core.Level.DEBUG, "PEERP", origin, helo, result);
            return true;
        }
    }
    
    public static void sendHeloToAll() {
        long time = System.currentTimeMillis();
        String connection = Core.getPeerConnection();
        if (connection != null) {
            String origin = null;
            String result = "SENT";
            String email = Core.getAdminEmail();
            String connectionSecured = Core.getPeerSecuredConnection();
            String helo;
            try {
                for (Peer peer : getSendAllSet()) {
                    if (connectionSecured != null && peer.isCompatible(2, 8)) {
                        helo = "HELO " + connectionSecured + " " + Core.getSubVersion() + (email == null ? "" : " " + email);
                    } else {
                        helo = "HELO " + connection + (email == null ? "" : " " + email);
                    }
                    String address = peer.getAddress();
                    int port = peer.getPort();
                    int ports = 0;
                    SecretKey key = null;
                    Core.sendCommandToPeer(
                            helo, address,
                            port, ports, key
                    );
                }
            } catch (Exception ex) {
                result = ex.getMessage();
            }
            helo = "HELO " + connection + " " + Core.getSubVersion() + (email == null ? "" : " " + email);
            Server.log(time, Core.Level.DEBUG, "PEERP", origin, helo, result);
        }
    }
    
    public void sendToRepass(String token) {
        long time = System.currentTimeMillis();
        if (Core.hasPeerConnection()) {
            String origin = null;
            String result = "SENT";
            try {
                for (Peer peer : getRepassSet()) {
                    String address = peer.getAddress();
                    int port = peer.getPort();
                    int ports = 0;
                    SecretKey key = null;
                    if (peer.isCompatible(2, 8)) {
                        ports = peer.getSecuredPort();
                        key = peer.getEncryptKey();
                    }
                    Core.sendCommandToPeer(
                            token, address,
                            port, ports, key
                    );
                }
            } catch (Exception ex) {
                result = ex.getMessage();
            }
            Server.logPeerSend(time, origin, token, result);
        }
    }
    
    protected static boolean isValidBlock(String token) {
        if (token == null || token.length() == 0) {
            return false;
        } else if (Subnet.isValidIP(token)) {
            return false;
        } else if (token.startsWith(".") && Domain.isHostname(token.substring(1))) {
            return true;
        } else if (token.contains("@") && Domain.isMailFrom(token)) {
            return true;
        } else if (token.startsWith("@") && Domain.containsDomain(token.substring(1))) {
            return true;
        } else {
            return false;
        }
    }
    
//    public static void sendToMirros(String command) {
//        long time = System.currentTimeMillis();
//        if (Core.hasPeerConnection()) {
//            String origin = null;
//            String result = "SENT";
//            try {
//                for (Peer mirror : getMirrorSet()) {
//                    String address = mirror.getAddress();
//                    int port = mirror.getPort();
//                    int ports = 0;
//                    SecretKey key = null;
//                    if (mirror.isCompatible(2, 8)) {
//                        ports = mirror.getSecuredPort();
//                        key = mirror.getEncryptKey();
//                    }
//                    Core.sendCommandToPeer(
//                            command, address,
//                            port, ports, key
//                    );
//                }
//            } catch (Exception ex) {
//                result = ex.getMessage();
//            }
//            Server.logPeerSend(time, origin, command, result);
//        }
//    }
    
    private boolean isReceiveDrop() {
        return receive == Receive.DROP;
    }
    
    private boolean isReceiveReject() {
        return receive == Receive.REJECT;
    }
    
    private boolean isReceiveRepass() {
        return receive == Receive.REPASS;
    }
    
    public String processBlock(String token) {
        try {
            if ((token = SPF.normalizeTokenFull(token)) == null) {
                return "INVALID";
            } else if (!isValidBlock(token)) {
                return "INVALID";
            } else if (Ignore.contains(token)) {
                return "IGNORED";
            } else if (isReceiveReject()) {
                return "REJECTED";
            } else if (isReceiveDrop()) {
                return "DROPPED";
            } else if (Block.containsExact(token)) {
                return "EXISTS";
            } else if (SPF.isGreen(token, false)) {
                return "GREEN";
            } else if (Block.addExact(token)) {
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
                try (FileOutputStream outputStream = new FileOutputStream(file)) {
                    SerializationUtils.serialize(map, outputStream);
                    // Atualiza flag de atualização.
                    CHANGED = false;
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
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    map = SerializationUtils.deserialize(fileInputStream);
                }
                for (Object key : map.keySet()) {
                    Object value = map.get(key);
                    if (key instanceof InetAddress) {
                        InetAddress address = (InetAddress) key;
                        Integer port = (Integer) value;
                        create(address.getHostAddress(), port, 0, 0);
                    } else if (key instanceof String) {
                        String address = (String) key;
                        if (value instanceof Integer) {
                            Integer port = (Integer) value;
                            create(address, port, 0, 0);
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
                                peer.receive = Receive.REPUTATION;
                            }
                            if (peer.receive == Receive.RETAIN) {
                                // Obsoleto.
                                peer.receive = Receive.REPUTATION;
                            }
                            if (peer.limit == 0) {
                                peer.limit = 100;
                            }
                            if (peer.reputationMap2 == null) {
                                peer.reputationMap2 = new TreeMap<>();
                            }
                            if (peer.frequencyMap == null) {
                                peer.frequencyMap = new TreeMap<>();
                            }
                            if (peer.reputationMap != null) {
                                peer.reputationMap2.putAll(peer.reputationMap);
                                peer.reputationMap.clear();
                            }
                            if (peer.version == 0) {
                                String adress = peer.getAddress();
                                if (adress.equals("matrix.spfbl.net")) {
                                    peer.setVersion("2.8");
                                }
                            }
                            MAP.put(address, peer);
                        }
                    }
                }
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        } else {
            try {
                if (Core.hasPeerConnection()) {
                    Peer matrix = Peer.create("matrix.spfbl.net", 9877, 9878, 443);
                    matrix.setReceiveStatus(Receive.ACCEPT);
                    matrix.setSendStatus(Send.REPUTATION);
                    matrix.setVersion("2.8");
                    matrix.sendHELO();
                }
            } catch (ProcessException ex) {
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
    
    public long getIdleTimeMillis() {
        if (last == 0) {
            return 0;
        } else {
            return System.currentTimeMillis() - last;
        }
    }
    
    public String getFrequencyLiteral() {
        if (hasFrequency()) {
            int frequencyInt = frequency.getMaximumInt();
            long idleTimeInt = getIdleTimeMillis();
            if (idleTimeInt > frequencyInt * 5 && idleTimeInt > 3600000) {
                return "DEAD";
            } else {
                char sinal = '~';
                if (frequencyInt < limit) {
                    frequencyInt = limit;
                    sinal = '<';
                } else if (idleTimeInt > frequencyInt * 3) {
                    sinal = '>';
                }
                if (frequencyInt >= 3600000) {
                    return sinal + ((frequencyInt / 3600000) + "h");
                } else if (frequencyInt >= 60000) {
                    return sinal + ((frequencyInt / 60000) + "min");
                } else if (frequencyInt >= 1000) {
                    return sinal + ((frequencyInt / 1000) + "s");
                } else {
                    return sinal + (frequencyInt + "ms");
                }
            }
        } else {
            return "UNDEFINED";
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
        String versionLocal = getVersion();
        User user = getUser();
        if (user == null) {
            return address + ":" + port + (ports == 0 ? "" : ":" + ports + (https == 443 ? "" : ":" + https))
                    + (versionLocal == null ? "" : " " + versionLocal)
                    + (send == null ? "" : " " + send.name())
                    + (receive == null ? "" : " " + receive.name())
                    + " " + getFrequencyLiteral() + " " + reputationMax
                    + (email == null ? "" : " <" + email + ">");
        } else {
            return address + ":" + port + (ports == 0 ? "" : ":" + ports + (https == 443 ? "" : ":" + https))
                    + (versionLocal == null ? "" : " " + versionLocal)
                    + (send == null ? "" : " " + send.name())
                    + (receive == null ? "" : " " + receive.name())
                    + " " + getFrequencyLiteral() + " " + reputationMax
                    + " " + user.getContact();
        }
    }
    
    protected String setReputation(
            String key,
            String ham,
            String spam,
            String frequencyXi,
            String frequencyXi2
    ) {
        try {
            if (!SPF.isValidReputation(key)) {
                return "INVALID";
            } else if (Generic.containsGenericSoft(key)) {
                return "GENERIC";
            } else if (Domain.isOfficialTLD(key)) {
                return "RESERVED";
            } else if (Subnet.isReservedIP(key)) {
                return "RESERVED";
            } else if (isReceiveReject()) {
                return "REJECTED";
            } else if (isReceiveDrop()) {
                return "DROPPED";
            } else {
                int hamInt = Integer.parseInt(ham);
                int spamInt = Integer.parseInt(spam);
                Binomial binomial;
                NormalDistribution frequencyLocal;
                if (hamInt == 0 && spamInt == 0) {
                    binomial = dropReputation(key);
                    if (binomial == null) {
                        return "NOT FOUND";
                    } else {
                        CHANGED = true;
                        return "DROPPED";
                    }
                } else if ((binomial = getReputation(key)) == null) {
                    binomial = new Binomial(hamInt, spamInt);
                    frequencyLocal = NormalDistribution.newDistribution(
                            frequencyXi, frequencyXi2
                    );
                    putReputation(key, binomial, frequencyLocal);
                    if (Ignore.contains(key)) {
                        binomial.clear();
                        return "IGNORED";
                    } else {
                        return "ADDED";
                    }
                } else {
                    binomial.set(hamInt, spamInt);
                    frequencyLocal = NormalDistribution.newDistribution(
                            frequencyXi, frequencyXi2
                    );
                    putReputation(key, frequencyLocal);
                    if (Ignore.contains(key)) {
                        binomial.clear();
                        return "IGNORED";
                    } else {
                        return "UPDATED";
                    }
                }
            }
        } catch (Exception ex) {
            return "INVALID";
        }
    }
    
    public boolean isExpired7() {
        return System.currentTimeMillis() - last > 604800000 &&
                System.currentTimeMillis() - create > 604800000;
    }
    
    public short getReputationMax() {
        return reputationMax;
    }
    
    private void refreshReputationMax() {
        reputationMax = (short) Math.max((int) (Core.getReputationLimit() * getCorrelacao()), 0);
        CHANGED = true;
    }
    
    public static void dropExpired() {
        String origin = null;
        for (Peer peer : getSet()) {
            long time = System.currentTimeMillis();
            if (peer.isExpired7()) {
                if (peer.drop()) {
                    Server.log(time, Core.Level.INFO, "PEERH", origin, peer.getAddress(), "EXPIRED");
                }
            } else {
                try {
                    peer.refreshReputationMax();
                    TreeMap<String, Binomial> reputationMap = peer.getReputationMap();
                    for (String key : reputationMap.keySet()) {
                        time = System.currentTimeMillis();
                        Binomial binomial = reputationMap.get(key);
                        if (binomial.isExpired3()) {
                            binomial = peer.dropReputation(key);
                            if (binomial != null) {
                                Server.log(time, Core.Level.INFO, "PEERR", peer.getAddress(), key, "EXPIRED");
                            }
                        }
                    }
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }
    }
    
    private synchronized Binomial dropReputation(String key) {
        if (reputationMap2 == null) {
            return null;
        } else {
            if (reputationMap2 == null) {
                reputationMap2 = new TreeMap<>();
            }
            if (frequencyMap == null) {
                frequencyMap = new TreeMap<>();
            }
            frequencyMap.remove(key);
            return reputationMap2.remove(key);
        }
    }
    
    private synchronized Binomial putReputation(
            String key,
            Binomial binomial,
            NormalDistribution frequency
    ) {
        if (reputationMap2 == null) {
            reputationMap2 = new TreeMap<>();
        }
        if (frequencyMap == null) {
            frequencyMap = new TreeMap<>();
        }
        if (frequency == null) {
            frequencyMap.remove(key);
        } else {
            frequencyMap.put(key, frequency);
        }
        return reputationMap2.put(key, binomial);
    }
    
    private synchronized NormalDistribution putReputation(
            String key,
            NormalDistribution frequency
    ) {
        if (frequencyMap == null) {
            frequencyMap = new TreeMap<>();
        }
        if (frequency == null) {
            return frequencyMap.remove(key);
        } else {
            return frequencyMap.put(key, frequency);
        }
    }
    
    public synchronized Binomial getReputation(String key) {
        if (reputationMap2 == null) {
            return null;
        } else {
            return reputationMap2.get(key);
        }
    }
    
    public static void clearReputation(String token) {
        for (Peer peer : Peer.getSet()) {
            Binomial repuation = peer.getReputation(token);
            if (repuation != null) {
                repuation.clear();
            }
        }
    }
    
    /**
     * Classe que representa a distribuição binomial entre HAM e SPAM.
     */
    public static final class Binomial implements Serializable {

        private static final long serialVersionUID = 1L;
        
        private int ham; // Quantidade total de HAM em sete dias.
        private int spam; // Quantidade total de SPAM em sete dias
        private long last = System.currentTimeMillis();
        private final Status status;
        
        public Binomial(int ham, int spam) throws ProcessException {
            this.status = null;
            set(ham, spam);
        }
        
        public Binomial(Status status) throws ProcessException {
            this.status = status;
            set(0, 0);
        }
        
        public synchronized void set(int ham, int spam) throws ProcessException {
            if (ham < 0) {
                throw new ProcessException("INVALID HAM VALUE");
            } else if (spam < 0) {
                throw new ProcessException("INVALID SPAM VALUE");
            } else if (this.ham != ham || this.spam != spam) {
                this.ham = ham;
                this.spam = spam;
                this.last = System.currentTimeMillis();
                CHANGED = true;
            }
        }
        
        public int getSPAM() {
            return spam;
        }
        
        public int getHAM() {
            return ham;
        }
        
        public int getTotalSize() {
            return ham + spam;
        }
        
        public Status getStatus() {
            return status;
        }
        
        public synchronized boolean clear() {
            if (spam > 0) {
                this.ham += spam;
                this.spam = 0;
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }
        
        public boolean isExpired3() {
            return System.currentTimeMillis() - last > 259200000;
        }

        public boolean isExpired7() {
            return System.currentTimeMillis() - last > 604800000;
        }

        public boolean hasLastUpdate() {
            return last > 0;
        }
        
        public synchronized float getSpamProbability() {
            if (ham + spam == 0) {
                return 0.0f;
            } else {
                return (float) spam / (float) (ham + spam);
            }
        }
        
        @Override
        public String toString() {
            return Float.toString(getSpamProbability());
        }
    }
}
