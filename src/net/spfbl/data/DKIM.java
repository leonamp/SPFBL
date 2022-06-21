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
 * along with SPFBL. If not, see <http://www.gnu.org/licenses/>.
 */
package net.spfbl.data;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.math.BigInteger;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import javax.naming.CommunicationException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.ServiceUnavailableException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import net.spfbl.core.Core;
import net.spfbl.core.ProcessException;
import net.spfbl.core.Server;
import net.spfbl.data.Reputation.Flag;
import static net.spfbl.data.Reputation.Flag.ACCEPTABLE;
import static net.spfbl.data.Reputation.Flag.HARMFUL;
import static net.spfbl.data.Reputation.Flag.UNACCEPTABLE;
import static net.spfbl.data.Reputation.Flag.UNDESIRABLE;
import net.spfbl.whois.Domain;
import org.apache.commons.lang3.SerializationException;
import org.apache.commons.lang3.SerializationUtils;

/**
 * DKIM implementation.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class DKIM {

    private final String zone;
    private long lastQuery;
    private Long refreshTime = null;
    private NamingException namingException = null;
    private PublicKey[] publicKeys = null;
    
    private DKIM(String zone) {
        this.zone = zone;
        this.lastQuery = System.currentTimeMillis();
    }
    
    private DKIM(
            String zone,
            long lastQuery,
            Long refreshTime,
            NamingException namingException,
            PublicKey[] publicKeys
    ) {
        this.zone = zone;
        this.lastQuery = lastQuery;
        this.refreshTime = refreshTime;
        this.namingException = namingException;
        this.publicKeys = publicKeys;
    }
    
    private synchronized boolean isExpired() {
        return System.currentTimeMillis() - lastQuery > Server.WEEK_TIME;
    }
    
    private synchronized String getLine() {
        StringBuilder builder = new StringBuilder();
        builder.append("DKIM ");
        builder.append(zone);
        builder.append(' ');
        builder.append(Long.toHexString(lastQuery));
        builder.append(' ');
        if (refreshTime == null) {
            builder.append("NULL");
        } else {
            builder.append(Long.toHexString(refreshTime));
        }
        builder.append(' ');
        if (namingException == null) {
            builder.append("NULL");
        } else {
            try {
                byte[] byteArray = SerializationUtils.serialize(namingException);
                builder.append(Core.BASE64STANDARD.encodeAsString(byteArray));
            } catch (SerializationException ex) {
                builder.append("NULL");
            } catch (Exception ex) {
                Server.logError(ex);
                builder.append("NULL");
            }
        }
        if (publicKeys != null) {
            for (PublicKey publicKey : publicKeys) {
                builder.append(' ');
                builder.append(Core.BASE64STANDARD.encodeAsString(publicKey.getEncoded()));
            }
        }
        return builder.toString();
    }
    
    private synchronized void whiteTo(FileWriter writer) throws IOException {
        writer.write(getLine());
        writer.write('\n');
        writer.flush();
    }
    
    private static final BigInteger MININAL_PUBLIC_EXPOENT = BigInteger.valueOf(65537);
    
    private synchronized PublicKey[] getPublicKeys()
            throws CommunicationException, NamingException {
        boolean expired;
        if (refreshTime == null) {
            expired = true;
        } else if (namingException == null) {
            expired = System.currentTimeMillis() - refreshTime > Server.DAY_TIME;
        } else {
            expired = System.currentTimeMillis() - refreshTime > Server.HOUR_TIME;
        }
        if (expired) {
            try {
                Attributes attributes = Server.getAttributesDNS(zone, "TXT");
                Attribute attribute = attributes.get("TXT");
                if (attribute == null) {
                    publicKeys = new PublicKey[0];
                } else {
                    int size = attribute.size();
                    ArrayList<PublicKey> publicKeyList = new ArrayList<>(size);
                    for (int index = 0; index < size; index++) {
                        String value = (String) attribute.get(index);
                        value = value.replaceAll("[ \"]+", "");
                        String v = "DKIM1";
                        String k = "rsa";
                        String p = null;
                        StringTokenizer tokenizer = new StringTokenizer(value, ";");
                        while (tokenizer.hasMoreTokens()) {
                            String token = tokenizer.nextToken().trim();
                            if (token.startsWith("v=")) {
                                v = token.substring(2);
                            } else if (token.startsWith("k=")) {
                                k = token.substring(2);
                            } else if (token.startsWith("p=")) {
                                p = token.substring(2);
                            }
                        }
                        if (v.equals("DKIM1") && p != null) {
                            try {
                                switch (k) {
                                    case "rsa":
                                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                                        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Core.BASE64STANDARD.decode(p));
                                        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
                                        BigInteger publicExpoent = publicKey.getPublicExponent();
                                        if (publicExpoent.compareTo(MININAL_PUBLIC_EXPOENT) < 0) {
                                            Server.logWarning("DKIM " + zone + " public key with too low expoent: " + publicExpoent);
                                        } else {
                                            publicKeyList.add(publicKey);
                                        }
                                }
                            } catch (InvalidKeySpecException ex) {
                                // Do nothing;
                            } catch (Exception ex) {
                                Server.logError(ex);
                            }
                        }
                    }
                    size = publicKeyList.size();
                    publicKeys = publicKeyList.toArray(new PublicKey[size]);
                }
                namingException = null;
            } catch (NameNotFoundException ex) {
                publicKeys = null;
                namingException = null;
            } catch (ServiceUnavailableException ex) {
                namingException = ex;
            } catch (CommunicationException ex) {
                if (ex.getCause() instanceof SocketTimeoutException) {
                    namingException = null;
                } else {
                    namingException = ex;
                }
            } catch (NamingException ex) {
                namingException = ex;
            } finally {
                refreshTime = System.currentTimeMillis();
            }
        }
        lastQuery = System.currentTimeMillis();
        append(getLine());
        if (namingException == null) {
            return publicKeys;
        } else {
            throw namingException;
        }
    }
    
    private static final HashMap<String,DKIM> CACHE = new HashMap<>();
    
    private static synchronized DKIM loadDKIM(String line) {
        if (line == null) {
            return null;
        } else {
            try {
                StringTokenizer tokenizer = new StringTokenizer(line, " ");
                String token = tokenizer.nextToken();
                if (token.equals("DKIM")) {
                    String zone = tokenizer.nextToken();
                    token = tokenizer.nextToken();
                    long lastQuery = Long.parseLong(token, 16);
                    token = tokenizer.nextToken();
                    Long refreshTime = (token.equals("NULL") ? null : Long.parseLong(token, 16));
                    token = tokenizer.nextToken();
                    NamingException namingException;
                    if (token.equals("NULL")) {
                        namingException = null;
                    } else {
                        byte[] byteArray = Core.BASE64STANDARD.decode(token);
                        namingException = SerializationUtils.deserialize(byteArray);
                    }
                    int count = tokenizer.countTokens();
                    PublicKey[] publicKeys = new PublicKey[count];
                    for (int index = 0; index < count; index++) {
                        token = tokenizer.nextToken();
                        byte[] byteArray = Core.BASE64STANDARD.decode(token);
                        X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(byteArray);
                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                        publicKeys[index] = keyFactory.generatePublic(encodedKeySpec);
                    }
                    DKIM dkim = new DKIM(zone, lastQuery, refreshTime, namingException, publicKeys);
                    CACHE.put(zone, dkim);
                    return dkim;
                } else {
                    return null;
                }
            } catch (Exception ex) {
                Server.logError(ex);
                return null;
            }
        }
    }
    
    private static synchronized TreeSet<String> getKeySet() {
        TreeSet<String> keySet = new TreeSet<>();
        keySet.addAll(CACHE.keySet());
        return keySet;
    }
    
    private static synchronized DKIM getDKIM(String zone, boolean create) {
        if (zone == null) {
            return null;
        } else {
            DKIM dkim = CACHE.get(zone);
            if (dkim == null && create) {
                dkim = new DKIM(zone);
                CACHE.put(zone, dkim);
            }
            return dkim;
        }
    }
    
    private static synchronized DKIM dropDKIM(String zone) {
        if (zone == null) {
            return null;
        } else {
            return CACHE.remove(zone);
        }
    }
    
    public static PublicKey[] getPublicKeys(
            String domain,
            String selector
    ) throws CommunicationException, NamingException {
        String zone = selector + "._domainkey." + domain;
        zone = zone.toLowerCase();
        DKIM dkim = getDKIM(zone, true);
        if (dkim == null) {
            return new PublicKey[0];
        } else {
            return dkim.getPublicKeys();
        }
    }
    
    private static enum Canonicalization {
        SIMPLE,
        RELAXED
    }
    
    private static Canonicalization[] getCanonicalizationPair(String c) {
        int index = c.indexOf('/');
        if (index == -1) {
            switch (c.toLowerCase()) {
                case "relaxed":
                    Canonicalization[] cArray1 = new Canonicalization[2];
                    cArray1[0] = Canonicalization.RELAXED;
                    cArray1[1] = Canonicalization.RELAXED;
                    return cArray1;
                case "simple":
                    Canonicalization[] cArray2 = new Canonicalization[2];
                    cArray2[0] = Canonicalization.SIMPLE;
                    cArray2[1] = Canonicalization.SIMPLE;
                    return cArray2;
                default:
                    return null;
            }
        } else {
            try {
                c = c.toUpperCase();
                Canonicalization[] cArray = new Canonicalization[2];
                cArray[0] = Canonicalization.valueOf(c.substring(0, index));
                cArray[1] = Canonicalization.valueOf(c.substring(index + 1));
                return cArray;
            } catch (Exception ex) {
                return null;
            }
        }
    }
    
    private static MessageDigest getMessageDigest(String a) {
        try {
            int index = a.indexOf('-');
            if (index == -1) {
                return null;
            } else if (a.endsWith("-sha1")) {
                return MessageDigest.getInstance("SHA-1");
            } else if (a.endsWith("-sha256")) {
                return MessageDigest.getInstance("SHA-256");
            } else {
                return null;
            }
        } catch (NoSuchAlgorithmException ex) {
            Server.logError(ex);
            return null;
        }
    }
    
    private static final File FILE = new File("./data/dkim.txt");
    private static Writer WRITER = null;
    private static final LinkedList<String> LIST = new LinkedList<>();
    private static final Semaphore SEMAPHORE = new Semaphore(0);
    
    private static void append(String line) {
        if (SEMAPHORE.tryAcquire()) {
            try {
                writeList();
                WRITER.append(line);
                WRITER.write('\n');
                WRITER.flush();
            } catch (Exception ex) {
                Server.logError(ex);
            } finally {
                SEMAPHORE.release();
            }
        } else {
            LIST.offer(line);
        }
    }
    
    private static void writeList() {
        try {
            String line;
            while ((line = LIST.poll()) != null) {
                WRITER.write(line);
                WRITER.write('\n');
            }
        } catch (Exception ex) {
            Server.logError(ex);
        }
    }
    
    private static void startWriter() {
        try {
            WRITER = new FileWriter(FILE, true);
            writeList();
            if (Core.isRunning()) {
                WRITER.flush();
            } else {
                WRITER.close();
            }
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
            if (Core.isRunning()) {
                SEMAPHORE.release();
            }
        }
    }
    
    public static void load() {
        long time = System.currentTimeMillis();
        if (FILE.exists()) {
            String line;
            try (BufferedReader reader = new BufferedReader(new FileReader(FILE))) {
                while ((line = reader.readLine()) != null) {
                    try {
                        if (line.startsWith("DKIM ")) {
                            DKIM.loadDKIM(line);
                        } else {
                            StringTokenizer tokenizer = new StringTokenizer(line, " ");
                            String token = tokenizer.nextToken();
                            if (token.equals("REP")) {
                                String domain = tokenizer.nextToken();
                                float xiSum = Float.parseFloat(tokenizer.nextToken());
                                float xi2Sum = Float.parseFloat(tokenizer.nextToken());
                                int last = Integer.parseInt(tokenizer.nextToken());
                                String flag = tokenizer.nextToken();
                                byte min = 0;
                                byte max = 0;
                                if (tokenizer.hasMoreTokens()) {
                                    min = Byte.parseByte(tokenizer.nextToken());
                                    max = Byte.parseByte(tokenizer.nextToken());
                                }
                                Node.load(domain, xiSum, xi2Sum, last, flag, min, max);
                            } else if (token.equals("QUEUE")) {
                                String domain = tokenizer.nextToken();
                                Byte value = tokenizer.hasMoreTokens() ? Byte.parseByte(tokenizer.nextToken()) : null;
                                addOperation(domain, value);
                            }
                        }
                    } catch (Exception ex) {
                        Server.logError(line);
                        Server.logError(ex);
                    }
                }
                Server.logLoad(time, FILE);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        startWriter();
    }

    public static boolean store() {
        try {
            long time = System.currentTimeMillis();
            SEMAPHORE.acquire();
            try {
                WRITER.close();
                Path source = FILE.toPath();
                Path temp = source.resolveSibling("." + FILE.getName());
                try (FileWriter writer = new FileWriter(temp.toFile())) {
                    for (String zone : getKeySet()) {
                        DKIM dkim = getDKIM(zone, false);
                        if (dkim != null) {
                            if (dkim.isExpired()) {
                                dropDKIM(zone);
                            } else {
                                dkim.whiteTo(writer);
                            }
                        }
                    }
                    ROOT.store(writer, ".");
                    THREAD.store(writer);
                }
                Files.move(temp, source, REPLACE_EXISTING);
                Server.logStore(time, FILE);
                return true;
            } finally {
                startWriter();
            }
        } catch (Exception ex) {
            Server.logError(ex);
            return false;
        }
    }
    
    public static class Signature {
        
        private final String algorithm;
        private final String query;
        private final String domain;
        private final long timestamp;
        private final String selector;
        private final String identity;
        private final String[] headerArray;
        private final Canonicalization headerCano;
        private final HashMap<String,String> headerMap = new HashMap<>();
        private final byte[] signatureBytes;
        private final int bodyLength;
        private final Canonicalization bodyCano;
        private final MessageDigest bodyDigest;
        private final byte[] bodyHash;
        private final long expiration;
        
        public Signature(String header) throws ProcessException {
            if (header == null) {
                throw new ProcessException("DKIM invalid signature.");
            } else if (!header.startsWith("DKIM-Signature:")) {
                throw new ProcessException("DKIM invalid signature.");
            } else {
                String v = "1";
                String a = "rsa-sha1";
                String q = "dns/txt";
                String c = "simple/simple";
                String d = null;
                String t = null;
                String s = null;
                String i = null;
                String h = null;
                String l = null;
                String bh = null;
                String b = null;
                String x = null;
                String value = header.substring(15);
                value = value.replaceAll("[ \t\r\n]+", "");
                StringTokenizer tokenizer = new StringTokenizer(value, ";");
                while (tokenizer.hasMoreTokens()) {
                    String token = tokenizer.nextToken();
                    if (token.startsWith("v=")) {
                        v = token.substring(2);
                    } else if (token.startsWith("a=")) {
                        a = token.substring(2);
                    } else if (token.startsWith("q=")) {
                        q = token.substring(2);
                    } else if (token.startsWith("c=")) {
                        c = token.substring(2);
                    } else if (token.startsWith("d=")) {
                        d = token.substring(2);
                    } else if (token.startsWith("t=")) {
                        t = token.substring(2);
                    } else if (token.startsWith("s=")) {
                        s = token.substring(2);
                    } else if (token.startsWith("i=")) {
                        i = token.substring(2);
                    } else if (token.startsWith("h=")) {
                        h = token.substring(2);
                    } else if (token.startsWith("l=")) {
                        l = token.substring(2);
                    } else if (token.startsWith("bh=")) {
                        bh = token.substring(3);
                    } else if (token.startsWith("x=")) {
                        x = token.substring(2);
                    } else if (token.startsWith("b=")) {
                        b = token.substring(2);
                    } else {
                        Server.logWarning("DKIM tag not reconized: " + token);
                    }
                }
                MessageDigest bDigest;
                Canonicalization[] cPair;
                if (!v.equals("1")) {
                    throw new ProcessException("DKIM version not supported: " + v);
                } else if (d == null) {
                    throw new ProcessException("DKIM tag domain not defined.");
                } else if (s == null) {
                    throw new ProcessException("DKIM tag selector not defined.");
                } else if (h == null) {
                    throw new ProcessException("DKIM tag header list not defined.");
                } else if (b == null) {
                    throw new ProcessException("DKIM tag header hash not defined.");
                } else if (t != null && !Core.isLong(t)) {
                    throw new ProcessException("DKIM invalid timestamp: " + t);
                } else if (l != null && !Core.isInteger(l)) {
                    throw new ProcessException("DKIM invalid body length: " + l);
                } else if (x != null && !Core.isLong(x)) {
                    throw new ProcessException("DKIM invalid expiration time: " + x);
                } else if ((bDigest = getMessageDigest(a)) == null) {
                    throw new ProcessException("DKIM algorithm not supported: " + a);
                } else if ((cPair = getCanonicalizationPair(c)) == null) {
                    throw new ProcessException("DKIM invalid canonicalization: " + c);
                } else {
                    tokenizer = new StringTokenizer(h, ":");
                    int count = tokenizer.countTokens();
                    String[] hArray = new String[count+1];
                    boolean hasFrom = false;
                    for (int index = 0; index < count; index++) {
                        String key = tokenizer.nextToken().toLowerCase();
                        if (!hasFrom && key.equals("from")) {
                            hasFrom = true;
                        }
                        hArray[index] = key;
                    }
                    hArray[count] = "DKIM-Signature";
                    if (hasFrom) {
                        algorithm = a;
                        query = q;
                        domain = d;
                        timestamp = (t == null ? 0 : Long.parseLong(t));
                        selector = s;
                        identity = i;
                        headerArray = hArray;
                        headerCano = cPair[0];
                        signatureBytes = Core.BASE64STANDARD.decode(b);
                        bodyLength = (l == null ? 0 : Integer.parseInt(l));
                        bodyCano = cPair[1];
                        bodyDigest = bDigest;
                        bodyHash = Core.BASE64STANDARD.decode(bh);
                        expiration = (x == null ? 0 : Long.parseLong(x));
                        for (int index = 0; index < count; index++) {
                            headerMap.put(hArray[index], null);
                        }
                        int index = header.lastIndexOf("b=") + 2;
                        header = header.substring(0, index);
                        headerMap.put("DKIM-Signature", header);
                    } else {
                        throw new ProcessException("DKIM header From not included.");
                    }
                }
            }
        }
        
        public String getDomain() {
            return domain;
        }
        
        public boolean hasIdentity() {
            return identity != null;
        }
        
        public String getIdentity() {
            return identity;
        }
        
        private java.security.Signature[] getVerifySignatures()
                throws CommunicationException, NamingException {
            if (algorithm.equals("rsa-sha1")) {
                PublicKey[] publicKeys = getPublicKeys(domain, selector);
                if (publicKeys == null) {
                    return null;
                } else {
                    int length = publicKeys.length;
                    ArrayList<java.security.Signature> signatureList = new ArrayList<>(length);
                    for (int index = 0; index < length; index++) {
                        try {
                            PublicKey publicKey = publicKeys[index];
                            if (publicKey instanceof RSAPublicKey) {
                                java.security.Signature signature = java.security.Signature.getInstance("SHA1withRSA");
                                signature.initVerify(publicKey);
                                signatureList.add(signature);
                            }
                        } catch (Exception ex) {
                            Server.logError(ex);
                        }
                    }
                    length = signatureList.size();
                    java.security.Signature[] signatureArray = new java.security.Signature[length];
                    signatureList.toArray(signatureArray);
                    return signatureArray;
                }
            } else if (algorithm.equals("rsa-sha256")) {
                PublicKey[] publicKeys = getPublicKeys(domain, selector);
                if (publicKeys == null) {
                    return null;
                } else {
                    int length = publicKeys.length;
                    ArrayList<java.security.Signature> signatureList = new ArrayList<>(length);
                    for (int index = 0; index < length; index++) {
                        try {
                            PublicKey publicKey = publicKeys[index];
                            if (publicKey instanceof RSAPublicKey) {
                                java.security.Signature signature = java.security.Signature.getInstance("SHA256withRSA");
                                signature.initVerify(publicKey);
                                signatureList.add(signature);
                            }
                        } catch (Exception ex) {
                            Server.logError(ex);
                        }
                    }
                    length = signatureList.size();
                    java.security.Signature[] signatureArray = new java.security.Signature[length];
                    signatureList.toArray(signatureArray);
                    return signatureArray;
                }
            } else {
                return new java.security.Signature[0];
            }
        }
        
        public boolean putHeader(String header) {
            if (header == null) {
                return false;
            } else {
                int index = header.indexOf(':');
                String key = header.substring(0, index).toLowerCase();
                if (headerMap.containsKey(key)) {
                    String value = headerMap.get(key);
                    if (value == null) {
                        headerMap.put(key, header);
                        return true;
                    }
                }
                return false;
            }
        }
        
        private transient int bodyEmptyLines = -1;
        
        public void bodyDigestUpdate(String line) {
            if (bodyEmptyLines == -1) {
                bodyEmptyLines = 0;
            }
            if (bodyCano == Canonicalization.RELAXED) {
                line = line.replaceFirst(" +$", "");
            }
            if (line.length() == 0) {
                bodyEmptyLines++;
            } else {
                if (bodyCano == Canonicalization.RELAXED) {
                    line = line.replaceAll("[ \\f]+", " ");
                }
                while (bodyEmptyLines > 0) {
                    bodyDigestUpdate((byte) '\r');
                    bodyDigestUpdate((byte) '\n');
                    bodyEmptyLines--;
                }
                try {
                    bodyDigestUpdate(line.getBytes("ISO-8859-1"));
                } catch (UnsupportedEncodingException ex) {
                    bodyDigestUpdate(line.getBytes());
                } finally {
                    bodyDigestUpdate((byte) '\r');
                    bodyDigestUpdate((byte) '\n');
                }
            }
        }
        
        private void bodyDigestUpdate(byte[] codeArray) {
            for (byte code : codeArray) {
                 if (!bodyDigestUpdate(code)) {
                     break;
                 }
            }
        }
        
        private transient int bodyDigestCount = 0;
        
        private boolean bodyDigestUpdate(byte code) {
            if (bodyLength == 0) {
                bodyDigest.update(code);
                return true;
            } else if (bodyDigestCount < bodyLength) {
                bodyDigest.update(code);
                bodyDigestCount++;
                return true;
            } else {
                return false;
            }
        }
        
        private transient Boolean bodyValid = null;
        private transient int bodyLatency = 0;
        
        public synchronized boolean isBodyValid() {
            if (bodyValid == null) {
                long startTime = System.currentTimeMillis();
                if (bodyEmptyLines == -1) {
                    bodyEmptyLines = 0;
                    if (bodyCano == Canonicalization.SIMPLE) {
                        bodyDigestUpdate((byte) '\r');
                        bodyDigestUpdate((byte) '\n');
                    }
                }
                bodyValid = Arrays.equals(bodyHash, bodyDigest.digest());
                bodyLatency = (int) (System.currentTimeMillis() - startTime);
            }
            return bodyValid;
        }
        
        private transient Boolean headerValid = null;
        private transient int headerLatency = 0;
        
        public boolean isHeaderValidSafe() {
            try {
                return isHeaderValid();
            } catch (Exception ex) {
                return false;
            }
        }
        
        public synchronized boolean isHeaderValid()
                throws CommunicationException, NamingException {
            if (headerValid == null) {
                long startTime = System.currentTimeMillis();
                java.security.Signature[] verifySignatures = getVerifySignatures();
                if (verifySignatures == null) {
                    return false;
                } else if (verifySignatures.length > 0) {
                    StringBuilder headerBuilder = new StringBuilder();
                    for (String key : headerArray) {
                        String header = headerMap.get(key);
                        if (header == null) {
                            return headerValid = false;
                        } else if (headerCano == Canonicalization.SIMPLE) {
                            headerBuilder.append(header);
                        } else if (headerCano == Canonicalization.RELAXED) {
                            key = key.toLowerCase().trim();
                            boolean crlf = header.endsWith("\r\n");
                            int index = header.indexOf(':') + 1;
                            String value = header.substring(index).trim();
                            value = value.replaceAll("\\s+", " ");
                            value = value.replaceAll("\r\n", "");
                            headerBuilder.append(key);
                            headerBuilder.append(':');
                            headerBuilder.append(value);
                            if (crlf) {
                                headerBuilder.append('\r');
                                headerBuilder.append('\n');
                            }
                        } else {
                            return headerValid = false;
                        }
                    }
                    byte[] headerHashByteArray = headerBuilder.toString().getBytes();
                    for (java.security.Signature signature : verifySignatures) {
                        try {
                            signature.update(headerHashByteArray);
                            if (signature.verify(signatureBytes)) {
                                return headerValid = true;
                            }
                        } catch (SignatureException ex) {
                            // Do nothing.
                        }
                    }
                }
                headerValid = false;
                headerLatency = (int) (System.currentTimeMillis() - startTime);
            }
            return headerValid;
        }
        
        public int getLatency() {
            return bodyLatency + headerLatency;
        }
        
        public boolean isValid() throws NamingException {
            return
                    isBodyValid() &&
                    isHeaderValid();
        }
        
        public String getResult() {
            try {
                if (isValid()) {
                    return "pass";
                } else {
                    return "fail";
                }
            } catch (NameNotFoundException ex) {
                return "permerror";
            } catch (NamingException ex) {
                return "temperror";
            }
        }
        
        public String getHeaderArrayToString() {
            StringBuilder builder = new StringBuilder();
            for (String header : headerArray) {
                if (builder.length() > 0) {
                    builder.append(':');
                }
                builder.append(header);
            }
            return builder.toString();
        }

        @Override
        public String toString() {
            return "algorithm=" + algorithm + ";"
                    + "query=" + query + ";"
                    + "domain=" + domain + ";"
                    + "timestamp=" + timestamp + ";"
                    + "selector=" + selector + ";"
                    + "identity=" + identity + ";"
                    + "headerList=" + getHeaderArrayToString() + ";"
                    + "headerCano=" + headerCano + ";"
                    + "headerHash=" + Core.BASE64STANDARD.encodeAsString(signatureBytes) + ";"
                    + "bodyLength=" + bodyLength + ";"
                    + "bodyCano=" + bodyCano + ";"
                    + "bodyHash=" + Core.BASE64STANDARD.encodeAsString(bodyHash) + ";"
                    + (expiration == 0 ? "" : "expirationTime=" + expiration + ";");
        }
    }
    
    private static final Node ROOT = new Node();
    
    public static boolean isBeneficial(String from, TreeSet<String> signerSet) {
        return getFlag(from, signerSet) == Flag.BENEFICIAL;
    }
    
    public static boolean addHarmful(String domain) {
        if (domain == null) {
            return false;
        } else {
            return addOperation(domain, (byte) -4);
        }
    }
    
    public static boolean addUndesirable(String domain) {
        if (domain == null) {
            return false;
        } else {
            return addOperation(domain, (byte) -2);
        }
    }
    
    public static boolean addUnacceptable(String domain) {
        if (domain == null) {
            return false;
        } else {
            return addOperation(domain, (byte) -1);
        }
    }
    
    public static boolean addAcceptable(String domain) {
        if (domain == null) {
            return false;
        } else {
            return addOperation(domain, (byte) 1);
        }
    }
    
    public static boolean addDesirable(String domain) {
        if (domain == null) {
            return false;
        } else {
            return addOperation(domain, (byte) 2);
        }
    }
    
    public static boolean addBeneficial(String domain) {
        if (domain == null) {
            return false;
        } else {
            return addOperation(domain, (byte) 4);
        }
    }
    
    private static boolean addOperation(String domain, Byte value) {
        if (domain == null) {
            return false;
        } else if (value == null) {
            return false;
        } else {
            THREAD.offer(new SimpleImmutableEntry<>(domain, value));
            return true;
        }
    }
    
    private static final ProcessThread THREAD = new ProcessThread();
    
    public static void startThread() {
        THREAD.start();
    }
    
    public static void terminateThread() {
        THREAD.terminate();
    }
    
    private static class ProcessThread extends Thread {
        
        private final LinkedList<SimpleImmutableEntry> QUEUE = new LinkedList<>();
        private boolean run = true;
        
        private ProcessThread() {
            super("DKIMTHRED");
            setPriority(Thread.MIN_PRIORITY);
        }
        
        private void offer(SimpleImmutableEntry<String,Byte> entry) {
            QUEUE.offer(entry);
            notifyQueue();
        }
        
        private SimpleImmutableEntry poll() {
            return QUEUE.poll();
        }
        
        private synchronized void waitNext() {
            try {
                wait(60000);
            } catch (InterruptedException ex) {
                Server.logError(ex);
            }
        }
        
        private boolean continueRun() {
            return run;
        }
        
        public void terminate() {
            run = false;
            notifyQueue();
        }
        
        public synchronized void notifyQueue() {
            notify();
        }
        
        @Override
        public void run() {
            try {
                Server.logTrace("thread started.");
                SimpleImmutableEntry<String,Byte> entry;
                while (Core.isRunning() && continueRun()) {
                    while (Core.isRunning() && (entry = poll()) != null) {
                        String sender = entry.getKey();
                        int index = sender.indexOf('@') + 1;
                        String domain = sender.substring(index);
                        byte value = entry.getValue();
                        if (value == -4 && Provider.containsExact('@' + domain)) {
                            value = -2;
                        } else if (value == 4 && Provider.containsExact('@' + domain)) {
                            value = 2;
                        }
                        int level = 0;
                        LinkedList<String> stack = new LinkedList<>();
                        StringTokenizer tokenizer = new StringTokenizer(domain, ".");
                        while (tokenizer.hasMoreTokens()) {
                            stack.push(tokenizer.nextToken());
                        }
                        Node reputation = ROOT;
                        String reverse = ".";
                        reputation.addValue(reverse, value, level);
                        Flag flag = reputation.refreshFlag(reverse, level, Flag.ACCEPTABLE);
                        while (!stack.isEmpty()) {
                            if (++level > 7) {
                                break;
                            } else {
                                String key = stack.pop();
                                reputation = reputation.newReputation(reverse, key);
                                if (reputation == null) {
                                    break;
                                } else {
                                    reverse += key + '.';
                                    reputation.addValue(reverse, value, level);
                                    flag = reputation.refreshFlag(reverse, level, flag);
                                }
                            }
                        }
                    }
                    waitNext();
                }
            } finally {
                Server.logTrace("thread closed.");
            }
        }
        
        private void store(FileWriter writer) throws IOException {
            if (!Core.isRunning()) {
                SimpleImmutableEntry<String,Byte> entry;
                while ((entry = poll()) != null) {
                    String domain = entry.getKey();
                    Byte value = entry.getValue();
                    writer.write("QUEUE ");
                    writer.write(domain);
                    if (value != null) {
                        writer.write(' ');
                        writer.write(Byte.toString(value));
                    }
                    writer.write('\n');
                    writer.flush();
                }
            }
        }
    }
    
    private static Flag getFlag(String domain, Flag defaultFlag) {
        if (domain == null) {
            return null;
        } else {
            LinkedList<String> stack = new LinkedList<>();
            StringTokenizer tokenizer = new StringTokenizer(domain, ".");
            while (tokenizer.hasMoreTokens()) {
                stack.push(tokenizer.nextToken());
            }
            Node node = ROOT;
            Flag flag = node.getFlag(defaultFlag);
            while (!stack.isEmpty()) {
                String key = stack.pop();
                node = node.getReputation(key);
                if (node == null) {
                    break;
                } else {
                    Flag newFlag = node.getFlag(flag);
                    if (newFlag == null) {
                        break;
                    } else {
                        flag = newFlag;
                    }
                }
            }
            return flag;
        }
    }
    
    public static Flag getFlag(String from, TreeSet<String> signerSet) {
        return getFlag(from, signerSet, false);
    }
    
    public static Flag getFlag(String from, TreeSet<String> signerSet, boolean signed) {
        if (from == null) {
            return UNACCEPTABLE;
        } else if (signerSet == null) {
            return UNACCEPTABLE;
        } else {
            int index = from.lastIndexOf('@') + 1;
            String domain = from.substring(index);
            if (signerSet.contains(domain)) {
                signed = true;
            }
            Flag flag = signed ? ACCEPTABLE : UNACCEPTABLE;
            flag = getFlag(domain, flag);
            if (signed) {
                return flag;
            } else if (flag == HARMFUL) {
                return flag;
            } else if (Ignore.containsExact('@' + domain)) {
                return HARMFUL;
            } else if (flag == UNDESIRABLE) {
                return flag;
            } else {
                return UNACCEPTABLE;
            }
        }
    }

    private static class Node extends Reputation {
        
        private static final int POPULATION[] = {
            16384, 8192, 4096, 2048, 1024, 512, 256, 128
        };
        
        private Node() {
            super();
        }
        
        private Node(Node other) {
            super(other, 2.0f);
        }
        
        private void addValue(String zone, int value, int level) {
            if (value == 4 && Domain.containsTLD(Domain.revert(zone))) {
                value = 1;
            } else if (value == 2 && Domain.containsTLD(Domain.revert(zone))) {
                value = 1;
            } else if (value == 4 && Provider.containsExact(Domain.revert(zone))) {
                value = 2;
            } else if (value == -4 && Domain.containsTLD(Domain.revert(zone))) {
                value = -2;
            }
            if (level == 0 && value > 1) {
                value = 1;
            }
            super.add(value, POPULATION[level]);
        }
        
        private TreeMap<String,Node> MAP = null;
        
        private synchronized Node newReputation(String zone, String key) {
            Flag flag = getFlag();
            byte[] extremes = getExtremes();
            byte minimum = extremes[0];
            byte maximum = extremes[1];
            if (key == null) {
                return null;
            } else if (flag == null) {
                return null;
            } else if (flag == Flag.HARMFUL && minimum == -4 && maximum == -4 && !Domain.containsTLD(Domain.revert(zone))) {
                MAP = null;
                return null;
            } else if (flag == Flag.UNDESIRABLE && minimum == -2 && maximum == -2 && !Domain.containsTLD(Domain.revert(zone))) {
                MAP = null;
                return null;
            } else if (flag == Flag.UNACCEPTABLE && minimum == -1 && maximum == -1 && !Domain.containsTLD(Domain.revert(zone))) {
                MAP = null;
                return null;
            } else if (flag == Flag.ACCEPTABLE && minimum == 1 && maximum == 1 && !Domain.containsTLD(Domain.revert(zone))) {
                MAP = null;
                return null;
            } else if (flag == Flag.DESIRABLE && minimum == 2 && maximum == 2 && !Domain.containsTLD(Domain.revert(zone))) {
                MAP = null;
                return null;
            } else if (flag == Flag.BENEFICIAL && minimum == 4 && maximum == 4 && !Domain.containsTLD(Domain.revert(zone)) && !Provider.containsExact(Domain.revert(zone))) {
                MAP = null;
                return null;
            } else {
                Node node = null;
                if (MAP == null) {
                    MAP = new TreeMap<>();
                } else {
                    node = MAP.get(key);
                }
                if (node == null) {
                    node = new Node(this);
                    MAP.put(key, node);
                }
                return node;
            }
        }
        
        private synchronized void clearMap() {
            MAP = null;
        }
        
        private synchronized void dropMap(String key) {
            if (MAP != null) {
                MAP.remove(key);
                if (MAP.isEmpty()) {
                    MAP = null;
                }
            }
        }
        
        private synchronized TreeSet<String> keySet() {
            TreeSet<String> keySet = new TreeSet<>();
            if (MAP != null) {
                keySet.addAll(MAP.keySet());
            }
            return keySet;
        }
        
        private synchronized Node getReputation(String key) {
            if (MAP == null) {
                return null;
            } else {
                return MAP.get(key);
            }
        }
        
        private Flag refreshFlag(String zone, int level, Flag defaultFlag) {
            Flag oldFlag = getFlag();
            Flag newFlag = refreshFlag(
                    POPULATION[level],
                    Domain.containsTLD(Domain.revert(zone))
            );
            if (newFlag != oldFlag) {
                float[] xisArray = getXiSum();
                byte[] extremes = getExtremes();
                int last = getLast();
                append(
                        "REP " + zone + " " + xisArray[0] + " " + xisArray[1]
                                + " " + last + " " + newFlag + " "
                                + extremes[0] + " " + extremes[1]
                );
            }
            if (newFlag == null) {
                return defaultFlag;
            } else {
                return newFlag;
            }
        }
        
        private static void load(
                String zone,
                float xiSum,
                float xi2Sum,
                int last,
                String flag,
                byte minimum,
                byte maximum
        ) {
            try {
                if (flag.equals("BENEFICIAL") && Domain.containsTLD(Domain.revert(zone))) {
                    flag = "ACCEPTABLE";
                } else if (flag.equals("DESIRABLE") && Domain.containsTLD(Domain.revert(zone))) {
                    flag = "ACCEPTABLE";
                } else if (flag.equals("BENEFICIAL") && Provider.containsExact(Domain.revert(zone))) {
                    flag = "DESIRABLE";
                } else if (flag.equals("HARMFUL") && Domain.containsTLD(Domain.revert(zone))) {
                    flag = "UNDESIRABLE";
                }
                StringTokenizer tokenizer = new StringTokenizer(zone, ".");
                Node node = ROOT;
                String zoneNode = ".";
                while (node != null && tokenizer.hasMoreTokens()) {
                    String key = tokenizer.nextToken();
                    node = node.newReputation(zoneNode, key);
                    zoneNode += key + '.';
                }
                if (node != null) {
                    node.set(xiSum, xi2Sum, last, flag, minimum, maximum);
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        
        private void store(FileWriter writer, String zone) throws IOException {
            float[] xiResult = getXiSum();
            Object flag = getFlagObject();
            byte[] extremes = getExtremes();
            int last = getLast();
            writer.write("REP ");
            writer.write(zone);
            writer.write(' ');
            writer.write(Float.toString(xiResult[0]));
            writer.write(' ');
            writer.write(Float.toString(xiResult[1]));
            writer.write(' ');
            writer.write(Integer.toString(last));
            writer.write(' ');
            writer.write(flag.toString());
            writer.write(' ');
            writer.write(Byte.toString(extremes[0]));
            writer.write(' ');
            writer.write(Byte.toString(extremes[1]));
            writer.write('\n');
            writer.flush();
            if (flag instanceof Integer) {
                clearMap();
            } else if (flag == Flag.HARMFUL && extremes[0] == -4 && extremes[1] == -4 && !Domain.containsTLD(Domain.revert(zone))) {
                clearMap();
            } else if (flag == Flag.UNDESIRABLE && extremes[0] == -2 && extremes[1] == -2 && !Domain.containsTLD(Domain.revert(zone))) {
                clearMap();
            } else if (flag == Flag.UNACCEPTABLE && extremes[0] == -1 && extremes[1] == -1 && !Domain.containsTLD(Domain.revert(zone))) {
                clearMap();
            } else if (flag == Flag.ACCEPTABLE && extremes[0] == 1 && extremes[1] == 1 && !Domain.containsTLD(Domain.revert(zone))) {
                clearMap();
            } else if (flag == Flag.DESIRABLE && extremes[0] == 2 && extremes[1] == 2 && !Domain.containsTLD(Domain.revert(zone))) {
                clearMap();
            } else if (flag == Flag.BENEFICIAL && extremes[0] == 4 && extremes[1] == 4 && !Domain.containsTLD(Domain.revert(zone)) && !Provider.containsExact(Domain.revert(zone))) {
                clearMap();
            } else {
                for (String key : keySet()) {
                    Node reputation = getReputation(key);
                    if (reputation != null) {
                        if (reputation.isExpired()) {
                            dropMap(key);
                        } else {
                            reputation.store(writer, zone + key + '.');
                        }
                    }
                }
            }
        }
    }
}
