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
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.TreeMap;
import java.util.TreeSet;
import javax.mail.internet.InternetAddress;
import javax.naming.NamingException;
import net.spfbl.data.Block;
import net.spfbl.data.Generic;
import net.spfbl.data.Provider;
import net.spfbl.data.White;
import net.spfbl.spf.SPF;
import net.spfbl.spf.SPF.Distribution;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Representa um usuário do sistema.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class User implements Serializable, Comparable<User> {
    
    private static final long serialVersionUID = 1L;
    
    private final String email;
    private String name;

    /**
     * Atributos para OTP.
     */
    private String otp_secret = null; // Chave oficial.
    private String otp_transition = null; // Chave de transição.
    private byte otp_fail = 0;
    private Integer otp_sucess = null;
    private long otp_last = 0;
    
    private User(String email, String name) throws ProcessException {
        if (Domain.isEmail(email) && simplify(name) != null) {
            this.email = email.toLowerCase();
            this.name = simplify(name);
        } else {
            throw new ProcessException("INVALID USER");
        }
    }
    
    public void setName(String name) throws ProcessException {
        if (simplify(name) != null && !this.name.equals(simplify(name))) {
            this.name = simplify(name);
            CHANGED = true;
        } else {
            throw new ProcessException("INVALID NAME");
        }
    }
    
    public String getEmail() {
        return email;
    }
    
    public String getDomain() {
        int index = email.indexOf('@') + 1;
        return email.substring(index);
    }
    
    public boolean isEmail(String email) {
        return this.email.equals(email);
    }
    
    public boolean hasSecretOTP() {
        return otp_secret != null;
    }
    
    public boolean hasTransitionOTP() {
        return otp_transition != null;
    }
    
    public String newSecretOTP() {
        CHANGED = true;
        return otp_transition = Core.generateSecretOTP();
    }
    
    public long getFailTime() {
        long thresholdTime = (long) Math.pow(2, otp_fail);
        long idleTime = System.currentTimeMillis() - otp_last;
        if (idleTime < 1000) {
            return 1000;
        } else {
            return thresholdTime - idleTime;
        }
        
    }
    
    public boolean tooManyFails() {
        long thresholdTime = (long) Math.pow(2, otp_fail);
        long idleTime = System.currentTimeMillis() - otp_last;
        if (idleTime < 1000) {
            return false;
        } else {
            return thresholdTime > idleTime;
        }
    }
    
    public boolean isValidOTP(Integer code) {
        if (code == null) {
            return false;
        } else if (code.equals(otp_sucess)) {
            return false;
        } else if (Core.isValidOTP(otp_transition, code)) {
            otp_secret = otp_transition;
            otp_transition = null;
            otp_fail = 0;
            otp_sucess = code;
            otp_last = System.currentTimeMillis();
            CHANGED = true;
            return true;
        } else if (Core.isValidOTP(otp_secret, code)) {
            otp_transition = null;
            otp_fail = 0;
            otp_sucess = code;
            otp_last = System.currentTimeMillis();
            CHANGED = true;
            return true;
        } else if (otp_fail < Byte.MAX_VALUE) {
            otp_fail++;
            otp_last = System.currentTimeMillis();
            CHANGED = true;
            return false;
        } else {
            otp_last = System.currentTimeMillis();
            CHANGED = true;
            return false;
        }
    }
    
    public String getName() {
        return name;
    }
    
    public InternetAddress getInternetAddress() {
        try {
            return new InternetAddress(email, name);
        } catch (UnsupportedEncodingException ex) {
            return null;
        }
    }
    
    private static String simplify(String text) {
        if (text == null) {
            return null;
        } else {
            char[] charArray = text.toCharArray();
            for (int i = 0; i < charArray.length; i++) {
                char character = charArray[i];
                if (character == '\n') {
                    charArray[i] = '\n';
                } else if (character == '“') {
                    charArray[i] = '"';
                } else if (character == '”') {
                    charArray[i] = '"';
                } else if (Character.isISOControl(character)) {
                    charArray[i] = ' ';
                }
            }
            text = new String(charArray);
            while (text.contains("  ")) {
                text = text.replace("  ", " ");
            }
            while (text.contains(" \n")) {
                text = text.replace(" \n", "\n");
            }
            while (text.contains("\n ")) {
                text = text.replace("\n ", "\n");
            }
            text = text.trim();
            if (text.length() == 0) {
                return null;
            } else {
                return text;
            }
        }
    }
    
    /**
     * Mapa de usuário com busca de hash O(1).
     */
    private static final HashMap<String,User> MAP = new HashMap<String,User>();
    
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean CHANGED = false;
    
    public synchronized static User create(String email,
            String name) throws ProcessException {
        if (MAP.containsKey(email)) {
            return null;
        } else {
            User user = new User(email, name);
            MAP.put(email, user);
            CHANGED = true;
            return user;
        }
    }
    
    public synchronized static TreeSet<User> getSet() {
        TreeSet<User> userSet = new TreeSet<User>();
        userSet.addAll(MAP.values());
        return userSet;
    }
    
    public synchronized static User drop(String email) {
        User user = MAP.remove(email);
        if (user != null) {
            CHANGED = true;
        }
        return user;
    }
    
    public static TreeSet<User> dropAll() {
        TreeSet<User> userSet = new TreeSet<User>();
        for (User user : getSet()) {
            String email = user.getEmail();
            user = drop(email);
            if (email != null) {
                userSet.add(user);
            }
        }
        return userSet;
    }
    
    public synchronized static User get(String email) {
        if (email == null) {
            return null;
        } else {
            return MAP.get(email);
        }
    }
    
    public static boolean exists(String email) {
        if (email == null) {
            return false;
        } else {
            return MAP.containsKey(email);
        }
    }
    
    public static synchronized HashMap<String,User> getMap() {
        HashMap<String,User> map = new HashMap<String,User>();
        map.putAll(MAP);
        return map;
    }
    
    public synchronized static void store() {
        if (CHANGED) {
            try {
                long time = System.currentTimeMillis();
                HashMap<String,User> map = getMap();
                File file = new File("./data/user.map");
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
        File file = new File("./data/user.map");
        if (file.exists()) {
            try {
                HashMap<String,Object> map;
                FileInputStream fileInputStream = new FileInputStream(file);
                try {
                    map = SerializationUtils.deserialize(fileInputStream);
                } finally {
                    fileInputStream.close();
                }
                for (String key : map.keySet()) {
                    Object value = map.get(key);
                    if (value instanceof User) {
                        User user = (User) value;
                        MAP.put(key, user);
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
        return email.hashCode();
    }
    
    @Override
    public boolean equals(Object o) {
        if (o instanceof User) {
            User other = (User) o;
            return this.email.equals(other.email);
        } else {
            return false;
        }
    }
    
    @Override
    public int compareTo(User other) {
        if (other == null) {
            return -1;
        } else {
            return this.toString().compareTo(other.toString());
        }
    }
    
    @Override
    public String toString() {
        return name + " <" + email + ">";
    }
    
    /**
     * Registro de consultas.
     */
    private TreeMap<Long,Query> queryMap = null;
    
    public void addQuery(
            long time,
            Client client,
            String ip,
            String helo,
            String hostname,
            String sender,
            String qualifier,
            String recipient,
            TreeSet<String> tokenSet,
            String result
    ) {
        SPF.Qualifier qualifierEnum;
        try {
            qualifierEnum = SPF.Qualifier.valueOf(qualifier);
        } catch (Exception ex) {
            qualifierEnum = null;
        }
        if (client == null) {
            addQuery(time, this.getDomain(), ip, helo, hostname, sender,
                    qualifierEnum, recipient, tokenSet, result
            );
        } else {
            addQuery(time, client.getDomain(), ip, helo, hostname, sender,
                    qualifierEnum, recipient, tokenSet, result
            );
        }
    }
    
    public void addQuery(
            long time,
            String client,
            String ip,
            String helo,
            String hostname,
            String sender,
            SPF.Qualifier qualifier,
            String recipient,
            TreeSet<String> tokenSet,
            String result
    ) {
        try {
            Query query = new Query(
                    client,
                    ip,
                    helo,
                    hostname,
                    sender,
                    qualifier,
                    recipient,
                    tokenSet,
                    result
            );
            putQuery(time, query);
        } catch (ProcessException ex) {
            Server.logError(ex);
        }
    }
    
    public synchronized TreeSet<Long> getQueryKeySet() {
        TreeSet<Long> keySet = new TreeSet<Long>();
        if (queryMap != null) {
            keySet.addAll(queryMap.keySet());
        }
        return keySet;
    }
    
    public void setResult(long time, String result) {
        if (result != null) {
            Query query = getQuery(time);
            if (query != null) {
                query.setResult(result);
            }
        }
    }
    
    public Query getQuery(String time) {
        try {
            return getQuery(Long.parseLong(time));
        } catch (NumberFormatException ex) {
            return null;
        }
    }
    
    public synchronized Query getQuery(long time) {
        if (queryMap == null) {
            return null;
        } else {
            return queryMap.get(time);
        }
    }
    
    public synchronized TreeSet<Long> getTimeSet() {
        if (queryMap == null) {
            return new TreeSet<Long>();
        } else {
            TreeSet<Long> timeSet = new TreeSet<Long>();
            timeSet.addAll(queryMap.keySet());
            return timeSet;
        }
    }
    
    private synchronized void putQuery(long time, Query query) {
        if (queryMap == null) {
            queryMap = new TreeMap<Long,Query>();
        }
        queryMap.put(time, query);
        if (queryMap.size() > 1024) {
            queryMap.pollFirstEntry();
        }
        CHANGED = true;
    }
    
    public enum Situation {
        
        NONE,
        ORIGIN,
        IP,
        ZONE,
        AUTHENTIC,
        SAME,
        ALL
        
    }
    
    public class Query implements Serializable {
        
        private static final long serialVersionUID = 1L;
        
        private String client;
        private String ip;
        private String helo;
        private String hostname = null;
        private String sender;
        private SPF.Qualifier qualifier;
        private String recipient;
        private final TreeSet<String> tokenSet = new TreeSet<String>();
        private String result;
        private String from = null;
        private String replyto = null;
        private TreeMap<String,Boolean> linkMap = null;
        private String malware = null;
        
        private Query(
                String client,
                String ip,
                String helo,
                String hostname,
                String sender,
                SPF.Qualifier qualifier,
                String recipient,
                TreeSet<String> tokenSet,
                String result
        ) throws ProcessException {
            if (!Domain.isHostname(client)) {
                throw new ProcessException("INVALID CLIENT");
            } else if (!Subnet.isValidIP(ip)) {
                throw new ProcessException("INVALID IP");
            } else if (sender != null && !sender.contains("@")) {
                throw new ProcessException("INVALID SENDER");
            } else if (recipient != null && !Domain.isEmail(recipient)) {
                throw new ProcessException("INVALID RECIPIENT");
            } else if (tokenSet == null) {
                throw new ProcessException("INVALID TOKEN SET");
            } else if (result == null) {
                throw new ProcessException("INVALID RESULT");
            } else {
               this.client = Domain.normalizeHostname(client, false);
               this.ip = Subnet.normalizeIP(ip);
               this.helo = helo;
               this.hostname = Domain.normalizeHostname(hostname, false);
               this.hostname = this.hostname == null ? "" : this.hostname;
               this.sender = sender;
               this.qualifier = qualifier;
               this.recipient = recipient;
               this.tokenSet.addAll(tokenSet);
               this.result = result;
               CHANGED = true;
            }
        }
        
        public String getClient() {
            return client;
        }

        public String getIP() {
            return ip;
        }

        public String getHELO() {
            if (helo == null) {
                return "";
            } else {
                return helo;
            }
        }
        
        public String getOrigin(boolean pontuacao) {
            String host = getValidHostname();
            if (host == null) {
                return ip;
            } else {
                return Domain.normalizeHostname(host, pontuacao);
            }
        }
        
        public TreeSet<String> getSenderMXDomainSet() throws NamingException {
            String host = getSenderHostname(false);
            TreeSet<String> mxSet = new TreeSet<String>();
            if (host != null) {
                for (String mx : Reverse.getMXSet(host)) {
                    try {
                        mxSet.add(Domain.extractDomain(mx, false));
                    } catch (ProcessException ex) {
                    }
                }
            }
            return mxSet;
        }
        
        public ArrayList<String> getSenderMXSet() {
            try {
                return Reverse.getMXSet(getSenderHostname(false));
            } catch (NamingException ex) {
                return null;
            }
        }
        
        public String getSenderHostname(boolean pontuacao) {
            String trueSender = getSender();
            if (trueSender == null) {
                return null;
            } else {
                int index = trueSender.indexOf('@');
                String host = trueSender.substring(index + 1);
                return Domain.normalizeHostname(host, pontuacao);
            }
        }
        
        public String getSenderDomain(boolean pontuacao) {
            String trueSender = getSender();
            if (trueSender == null) {
                return null;
            } else {
                int index = trueSender.indexOf('@');
                try {
                    String host = trueSender.substring(index + 1);
                    return Domain.extractDomain(host, pontuacao);
                } catch (ProcessException ex) {
                    return trueSender.substring(index);
                }
            }
        }
        
        public String getSender() {
            if (sender == null && from != null) {
                return from;
            } else if (sender == null && replyto != null) {
                return replyto;
            } else if (sender == null && getValidHostname() != null && !Generic.contains(getValidHostname())) {
                return "mailer-daemon@" + getValidHostname();
            } else if (Provider.containsMX(sender) && Domain.isValidEmail(sender)) {
                return sender;
            } else if (Provider.containsDomain(getValidHostname()) && Provider.containsDomain(sender)) {
                return from == null ? replyto : from;
            } else if (Domain.isValidEmail(sender)) {
                return sender;
            } else if (Domain.isValidEmail(from)) {
                return from;
            } else if (Domain.isValidEmail(replyto)) {
                return replyto;
            } else if (Domain.isEmail(sender)) { // Temporário.
                return sender;
            } else if (from != null) {
                return from;
            } else {
                return replyto;
            }
        }
        
        public String getSenderSimplified(boolean byDomain, boolean pontuacao) {
            String trueSender = getSender();
            if (trueSender == null) {
                return null;
            } else if (trueSender.startsWith("mailer-daemon@")) {
                return trueSender;
            } else if (Provider.containsMX(trueSender)) {
                if (Domain.isValidEmail(trueSender)) {
                    return trueSender;
                } else {
                    int index = trueSender.indexOf('@');
                    return trueSender.substring(index);
                }
            } else if (byDomain) {
                int index = trueSender.indexOf('@');
                try {
                    String host = trueSender.substring(index + 1);
                    return Domain.extractDomain(host, pontuacao);
                } catch (ProcessException ex) {
                    return trueSender.substring(index);
                }
            } else {
                int index = trueSender.indexOf('@');
                return trueSender.substring(index);
            }
        }

        public String getQualifierName() {
            if (qualifier == null) {
                return "NONE";
            } else {
                String trueSender = getSender();
                if (trueSender == null) {
                    return "NONE";
                } else if (trueSender.equals(sender)) {
                    return qualifier.name();
                } else {
                    return "NONE";
                }
            }
        }
        
        public String getValidHostname() {
            if (hostname != null) {
                return hostname.length() == 0 ? null : hostname;
            } else if (SPF.matchHELO(ip, helo)) {
                return hostname = helo;
            } else {
                String host = Reverse.getValidHostname(ip);
                if (host == null) {
                    hostname = "";
                    return null;
                } else if (Generic.containsDomain(host)) {
                    hostname = "";
                    return null;
                } else {
                    return hostname = Domain.normalizeHostname(host, false);
                }
            } 
        }
        
        public String getValidHostDomain() {
            try {
                String host = getValidHostname();
                return Domain.extractDomain(host, false);
            } catch (ProcessException ex) {
                return null;
            }
        }
        
        public String getValidator(boolean authentic) {
            if (getSender() == null) {
                return null;
            } else if (authentic && getQualifierName().equals("PASS")) {
                return "PASS";
            } else {
                String domain = getValidHostDomain();
                if (domain == null) {
                    return ip;
                } else {
                    return domain;
                }
            }
        }

        public String getRecipient() {
            return recipient;
        }

        public String getResult() {
            return result;
        }
        
        private String getComplainKey() {
            String key = getSenderSimplified(true, true);
            if (key == null) {
                return getOrigin(true);
            } else {
                return key;
            }
        }
        
        public void processComplain() {
            String complainKey = getComplainKey();
            for (long time : getTimeSet().descendingSet()) {
                Query query = getQuery(time);
                if (query != null && complainKey.equals(query.getComplainKey())) {
                    if (query.isWhite()) {
                        clearBlock();
                        if (!query.hasMalware()) {
                            SPF.setHam(time, query.getTokenSet());
                        }
                    } else if (query.isBlock()) {
                        SPF.setSpam(time, query.getTokenSet());
                    }
                }
            }
        }
        
        public void clearWhite() {
            try {
                White.clear(null, User.this, ip, sender, getValidHostname(), qualifier == null ? "NONE" : qualifier.name(), recipient);
            } catch (ProcessException ex) {
                Server.logError(ex);
            }
            try {
                White.clear(null, User.this, ip, getSender(), getValidHostname(), getQualifierName(), recipient);
            } catch (ProcessException ex) {
                Server.logError(ex);
            }
        }
        
        public void clearBlock() {
            try {
                Block.clear(null, User.this, ip, sender, getValidHostname(), qualifier == null ? "NONE" : qualifier.name(), recipient);
            } catch (ProcessException ex) {
                Server.logError(ex);
            }
            try {
                Block.clear(null, User.this, ip, getSender(), getValidHostname(), getQualifierName(), recipient);
            } catch (ProcessException ex) {
                Server.logError(ex);
            }
            if (linkMap != null) {
                for (String link : linkMap.keySet()) {
                    Block.clear(link, email);
                }
            }
        }
        
        public boolean block(long time, String situationName) throws ProcessException {
            try {
                Situation situation = Situation.valueOf(situationName);
                clearWhite();
                SPF.setSpam(time, tokenSet);
                switch (situation) {
                    case ORIGIN:
                        return Block.add(User.this, "@;" + getOrigin(false));
                    case ZONE:
                    case IP:
                        return Block.add(User.this, getSenderDomain(true) + ";NOTPASS");
                    case SAME:
                        String validator = getValidator(false);
                        if (validator == null) {
                            return false;
                        } else {
                            return Block.add(User.this, getSenderSimplified(true, true) + ";" + validator);
                        }
                    case ALL:
                        String senderSimplified = getSenderSimplified(true, true);
                        if (SPF.isNotGreen(senderSimplified)) {
                            if (Block.addExact(senderSimplified)) {
                                Server.logDebug("new BLOCK '" + senderSimplified + "' added by '" + email + "'.");
                                Peer.sendBlockToAll(senderSimplified);
                            }
                        }
                        return Block.add(User.this, senderSimplified);
                    default:
                        return false;
                }
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        }
        
        public boolean white(long time, String situationName) throws ProcessException {
            try {
                Situation situation = Situation.valueOf(situationName);
                clearBlock();
                SPF.setHam(time, tokenSet);
                switch (situation) {
                    case ORIGIN:
                        return White.add(User.this, "@;" + getOrigin(false));
                    case IP:
                        return White.add(User.this, getSenderSimplified(false, true) + ";" + ip);
                    case ZONE:
                        String domain = getValidHostDomain();
                        if (domain == null) {
                            return false;
                        } else {
                            return White.add(User.this, getSenderSimplified(false, true) + ";" + domain);
                        }
                    case AUTHENTIC:
                        return White.add(User.this, getSenderSimplified(false, true) + ";PASS");
                    case SAME:
                        String validator = getValidator(false);
                        if (validator == null) {
                            return false;
                        } else {
                            return White.add(User.this, getSenderSimplified(false, true) + ";" + validator);
                        }
                    default:
                        return false;
                }
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        }
        
        public boolean hasMalware() {
            return malware != null;
        }
        
        public boolean isWhite() {
            return White.find(null, User.this, ip, getSender(), getValidHostname(), getQualifierName(), recipient) != null;
        }
        
        public String getWhite() {
            return White.find(null, User.this, ip, getSender(), getValidHostname(), getQualifierName(), recipient);
        }
        
        public boolean isBlock() {
            return Block.find(null, User.this, ip, getSender(), getValidHostname(), getQualifierName(), recipient, true) != null;
        }
        
        public String getBlock() {
            return Block.find(null, User.this, ip, getSender(), getValidHostname(), getQualifierName(), recipient, true);
        }
        
        public boolean isSenderWhite() {
            String validator = getValidator(true);
            if (validator == null) {
                return false;
            } else {
                return White.containsExtact(User.this, getSenderSimplified(false, true) + ';' + validator);
            }
        }
        
        public boolean isOriginWhite() {
            return White.containsExtact(User.this, "@;" + getOrigin(false));
        }
        
        public boolean isSenderBlock(boolean valid) {
            if (valid) {
                return Block.containsExact(User.this, getSenderDomain(true) + ";NOTPASS");
            } else {
                return Block.containsExact(User.this, getSenderSimplified(true, true));
            }
        }
        
        public boolean isOriginBlock() {
            return Block.containsExact(User.this, "@;" + getOrigin(false));
        }
        
        public boolean isSenderRed() {
            String tueSender = getSender();
            if (tueSender == null) {
                return false;
            } else if (getQualifierName().equals("PASS")) {
                String token;
                if (Provider.containsMX(tueSender)) {
                    token = tueSender;
                } else {
                    int index = tueSender.indexOf('@');
                    token = tueSender.substring(index);
                }
                Distribution distribution = SPF.getDistribution(token);
                if (distribution == null) {
                    return false;
                } else {
                    return distribution.isRed();
                }
            } else {
                return false;
            }
        }
        
        public boolean isFail() {
            return getQualifierName().equals("FAIL");
        }
        
        public boolean isSoftfail() {
            return getQualifierName().equals("SOFTFAIL");
        }
        
        public boolean isRed() {
            return SPF.isRed(tokenSet);
        }
        
        public boolean isYellow() {
            return SPF.isRed(tokenSet);
        }
        
        public TreeSet<String> getLinkSet() {
            if (linkMap == null) {
                return null;
            } else {
                TreeSet<String> resultSet = new TreeSet<String>();
                resultSet.addAll(linkMap.keySet());
                return resultSet;
            }
        }
        
        public TreeSet<String> getTokenSet() {
            TreeSet<String> resultSet = new TreeSet<String>();
            resultSet.addAll(tokenSet);
            return resultSet;
        }
        
        public String getMalware() {
            return malware;
        }
        
        public boolean setResult(String result) {
            if (result == null) {
                return false;
            } else if (result.equals("MALWARE")) {
                this.malware = "FOUND";
                this.result = "REJECT";
                return CHANGED = true;
            } else if (!result.equals(this.result)) {
                this.result = result;
                return CHANGED = true;
            } else {
                return false;
            }
        }
        
        public String getFrom() {
            return from;
        }
        
        public String getReplyTo() {
            return replyto;
        }
        
        public boolean isLinkBlocked(String link) {
            if (linkMap == null) {
                return false;
            } else {
                Boolean blocked = linkMap.get(link);
                if (blocked == null) {
                    return false;
                } else {
                    return blocked;
                }
            }
        }
        
        public boolean addLink(String link) {
            if (link == null) {
                return false;
            } else {
                if (this.linkMap == null) {
                    this.linkMap = new TreeMap<String,Boolean>();
                }
                boolean blocked = false;
                if (Block.find(User.this, link) == null) {
                    this.linkMap.put(link, false);
                } else {
                    this.linkMap.put(link, true);
                    blocked = true;
                }
                CHANGED = true;
                return blocked;
            }
        }
        
        public boolean setLinkSet(TreeSet<String> linkSet) {
            if (linkSet == null) {
                return false;
            } else {
                if (this.linkMap == null) {
                    this.linkMap = new TreeMap<String,Boolean>();
                }
                boolean blocked = false;
                for (String link : linkSet) {
                    if (Block.find(User.this, link) == null) {
                        this.linkMap.put(link, false);
                    } else {
                        this.linkMap.put(link, true);
                        blocked = true;
                    }
                }
                CHANGED = true;
                return blocked;
            }
        }
        
        public void setMalware(String malware) {
            if (malware != null && !malware.equals(this.malware)) {
                this.malware = malware;
                this.result = "REJECT";
                CHANGED = true;
            }
        }
        
        public String setFrom(String from, String replyto, String unsubscribe) {
            if (from == null) {
                if (this.from != null) {
                    this.from = null;
                    CHANGED = true;
                }
            } else if (Domain.isEmail(from = from.toLowerCase()) && !from.equals(this.from)) {
                this.from = from;
                CHANGED = true;
            }
            if (replyto == null) {
                if (this.replyto != null) {
                    this.replyto = null;
                    CHANGED = true;
                }
            } else if (Domain.isEmail(replyto = replyto.toLowerCase()) && !replyto.equals(this.replyto)) {
                this.replyto = replyto;
                CHANGED = true;
            }
            boolean reject = false;
            if (unsubscribe != null) {
                try {
                    int index = unsubscribe.indexOf('<');
                    if (index >= 0) {
                        unsubscribe = unsubscribe.substring(index+1);
                        index = unsubscribe.indexOf('>');
                        if (index > 0) {
                            unsubscribe = unsubscribe.substring(0, index);
                            index = unsubscribe.indexOf('?');
                            if (index > 0) {
                                unsubscribe = unsubscribe.substring(0, index);
                            }
                            URI uri = new URI(unsubscribe);
                            reject = addLink(uri.getHost());
                        }
                    }
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
            if (isWhite()) {
                clearBlock();
                return this.result = "WHITE";
            } else if (isBlock()) {
                clearWhite();
                this.result = "BLOCK";
                return "BLOCKED";
            } else if (reject) {
                this.result = "REJECT";
                return "BLOCKED";
            } else {
                return null;
            }
        }
        
        public boolean isSpam(long time) {
            for (String token : tokenSet) {
                Distribution distribution = SPF.getDistribution(token);
                if (distribution != null && distribution.isSpam(time)) {
                    return true;
                }
            }
            return false;
        }
        
        public Situation getSituation() {
            String validator = getValidator(true);
            if (validator == null) {
                return Situation.ORIGIN;
            } else if (validator.equals("PASS")) {
                return Situation.AUTHENTIC;
            } else if (Subnet.isValidIP(validator)) {
                return Situation.IP;
            } else {
                return Situation.ZONE;
            }
        }
        
        public Situation getSenderWhiteSituation() {
            if (isSenderWhite()) {
                String validator = getValidator(true);
                if (validator == null) {
                    return Situation.ORIGIN;
                } else if (validator.equals("PASS")) {
                    return Situation.AUTHENTIC;
                } else if (Subnet.isValidIP(validator)) {
                    return Situation.IP;
                } else {
                    return Situation.ZONE;
                }
            } else if (isOriginWhite()) {
                return Situation.ORIGIN;
            } else if (isWhite()) {
                return Situation.SAME;
            } else {
                return Situation.NONE;
            }
        }
        
        public Situation getSenderBlockSituation() {
            if (isSenderBlock(false)) {
                return Situation.ALL;
            } else if (isSenderBlock(true)) {
                String validator = getValidator(false);
                if (validator == null) {
                    return Situation.ORIGIN;
                } else if (Subnet.isValidIP(validator)) {
                    return Situation.IP;
                } else {
                    return Situation.ZONE;
                }
            } else if (isOriginBlock()) {
                return Situation.ORIGIN;
            } else if (isBlock()) {
                return Situation.SAME;
            } else {
                return Situation.NONE;
            }
        }
        
        @Override
        public String toString() {
            return client + ": " + (helo == null ? ip : helo + " [" + ip + "]")
                    + (getSender() == null ? "" : " " + getSender())
                    + " " + getQualifierName() + " > " + recipient + " = " + result;
        }
    }
}
