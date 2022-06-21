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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Objects;
import java.util.StringTokenizer;
import java.util.TreeSet;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import net.spfbl.core.Client;
import net.spfbl.core.Core;
import net.spfbl.core.Defer;
import net.spfbl.core.Filterable;
import net.spfbl.core.Filterable.Filter;
import net.spfbl.core.ProcessException;
import static net.spfbl.core.Regex.isHostname;
import static net.spfbl.core.Regex.isValidEmail;
import static net.spfbl.core.Regex.isValidIP;
import net.spfbl.core.Server;
import net.spfbl.core.User;
import net.spfbl.spf.SPF.Qualifier;
import net.spfbl.whois.Domain;
import net.spfbl.spf.SPF;
import net.spfbl.whois.Subnet;
import org.jose4j.json.internal.json_simple.JSONObject;

/**
 * Represents the licence structure.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Licence {
    
    private static final long serialVersionUID = 1L;
    
    private final String email;
    private Locale locale;
    private int fuel;
    
    private Licence(String email) {
        this.email = email;
        this.locale = Locale.getDefault();
        this.fuel = 1;
    }
    
    public String getUserEmail() {
        return email;
    }
    
    public boolean isWithoutFuel() {
        return fuel == 0;
    }
    
    public synchronized boolean consume() { 
        if (fuel > 0) {
            fuel--;
            return true;
        } else {
            return false;
        }
    }
        
    @Override
    public int hashCode() {
        return Objects.hash(
                "Licence", Licence.serialVersionUID, email
        );
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof Licence) {
            final Licence other = (Licence) obj;
            return Objects.equals(this.email, other.email);
        } else {
            return false;
        }
    }
    
    public String getLicenceURL(long expiration, String client) {
        try {
            byte[] byteArray = getByteArray(expiration, client);
            String encrypted = Server.encryptURLSafe(byteArray);
            String command = "licence/" + encrypted;
            return Core.getURL(true, null, command);
        } catch (Exception ex) {
            Server.logError(ex);
            return null;
        }
    }
    
    public byte[] getByteArray(long expiration, String client) throws Exception {
        if (client == null) {
            return null;
        } else {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (GZIPOutputStream gzos = new GZIPOutputStream(baos)) {
                try (DataOutputStream dos =  new DataOutputStream(gzos)) {
                    int hashCode = Objects.hash(
                            "Licence", Licence.serialVersionUID, email,
                            client, expiration
                    );
                    dos.writeInt(hashCode);
                    Core.writeUTF(dos, email);
                    Core.writeUTF(dos, client);
                    dos.writeLong(expiration);
                }
            }
            return baos.toByteArray();
        }
    }
    
    public static Licence getLicence(String email) {
        if ((email = Domain.normalizeEmail(email)) == null) {
            return null;
        } else {
            return new Licence(email);
        }
    }
    
    public Message newMessage(String client, HashMap<String,Object> parameterMap) {
        if (parameterMap == null) {
            return null;
        } else if (parameterMap.isEmpty()) {
            return null;
        } else if ((client = Domain.normalizeHostname(client, false)) == null) {
            return null;
        } else {
            try {
                String ip = null;
                String helo = null;
                String fqdn = null;
                String sender = null;
                String result = null;
                String from = null;
                String replyTo = null;
                String subject = null;
                String messageID = null;
                String inReplyTo = null;
                String queueID = null;
                String dateString = null;
                String unsubscribeString = null;
                String recipientList = null;
                String signerList = null;
                String linkList = null;
                String executableList = null;
                String malware = null;
                for (String key : parameterMap.keySet()) {
                    Object value = parameterMap.get(key);
                    if (value instanceof String) {
                        switch (key) {
                            case "ip":
                                ip = (String) value;
                                break;
                            case "helo":
                                helo = (String) value;
                                break;
                            case "fqdn":
                                fqdn = (String) value;
                                break;
                            case "sender":
                                sender = (String) value;
                                break;
                            case "result":
                                result = (String) value;
                            case "from":
                                from = (String) value;
                                break;
                            case "replyto":
                                replyTo = (String) value;
                                break;
                            case "subject":
                                subject = (String) value;
                                break;
                            case "messageid":
                                messageID = (String) value;
                                break;
                            case "inreplyto":
                                inReplyTo = (String) value;
                                break;
                            case "queueid":
                                queueID = (String) value;
                                break;
                            case "date":
                                dateString = (String) value;
                                break;
                            case "unsubscribe":
                                unsubscribeString = (String) value;
                                break;
                            case "recipient":
                                recipientList = (String) value;
                                break;
                            case "signer":
                                signerList = (String) value;
                                break;
                            case "link":
                                linkList = (String) value;
                                break;
                            case "executable":
                                executableList = (String) value;
                                break;
                            case "malware":
                                malware = (String) malware;
                                break;
                            default:
                                Server.logError("undefined parameter: " + key + "=" + value);
                        }
                    }
                }
                ip = Subnet.normalizeIP(ip);
                if (ip == null) {
                    return null;
                }
                if (helo == null) {
                    return null;
                }
                if (!FQDN.addFQDN(ip, fqdn, true)) {
                    fqdn = null;
                }
                if (fqdn == null) {
                    if (!isHostname(helo)) {
                        fqdn = FQDN.getFQDN(ip, false);
                    } else if (Generic.containsGenericFQDN(helo)) {
                        fqdn = FQDN.getFQDN(ip, false);
                    } else if (FQDN.isFQDN(ip, helo)) {
                        fqdn = Domain.normalizeHostname(helo, false);
                    } else if (FQDN.addFQDN(ip, helo, true)) {
                        fqdn = Domain.normalizeHostname(helo, false);
                    } else {
                        fqdn = FQDN.getFQDN(ip, false);
                    }
                }
                Qualifier qualifier = Qualifier.get(result);
                if (sender == null) {
                    return null;
                } else if (sender.isEmpty()) {
                    sender = null;
                } else if (Domain.isMailFrom(sender)) {
                    if (qualifier == null) {
                        qualifier = SPF.getQualifier(ip, sender, helo, false);
                    } else {
                        qualifier = SPF.getQualifierIfExists(ip, sender, helo, qualifier);
                    }
                }
                TreeSet<String> recipientSet = null;
                if (recipientList != null) {
                    recipientSet = new TreeSet<>();
                    StringTokenizer tokenizer = new StringTokenizer(recipientList, ",");
                    while (tokenizer.hasMoreTokens()) {
                        String token = tokenizer.nextToken().trim();
                        String recipient = Domain.normalizeEmail(token);
                        if (recipient != null) {
                            recipientSet.add(recipient);
                        }
                    }
                }
                TreeSet<String> signerSet = null;
                if (signerList != null) {
                    signerSet = new TreeSet<>();
                    StringTokenizer tokenizer = new StringTokenizer(signerList, ",");
                    while (tokenizer.hasMoreTokens()) {
                        String token = tokenizer.nextToken().trim();
                        String signer = Domain.normalizeHostname(token, false);
                        if (signer != null) {
                            signerSet.add(signer);
                        }
                    }
                }
                TreeSet<String> linkSet = null;
                if (linkList != null) {
                    linkSet = new TreeSet<>();
                    StringTokenizer tokenizer = new StringTokenizer(linkList, ",");
                    while (tokenizer.hasMoreTokens()) {
                        String token = tokenizer.nextToken().trim();
                        String link = Domain.normalizeHostname(token, false);
                        if (link != null) {
                            linkSet.add(link);
                        }
                    }
                }
                TreeSet<String> executableSet = null;
                if (executableList != null) {
                    executableSet = new TreeSet<>();
                    StringTokenizer tokenizer = new StringTokenizer(executableList, ",");
                    while (tokenizer.hasMoreTokens()) {
                        String token = tokenizer.nextToken().trim();
                        String executable = Domain.normalizeHostname(token, false);
                        if (executable != null) {
                            executableSet.add(executable);
                        }
                    }
                }
                boolean forgedFrom = false;
                boolean spoofedRecipient = false;
                if (from == null) {
                    return null;
                } else if (from.isEmpty()) {
                    from = null;
                } else {
                    try {
                        from = from.replaceAll("[\\s\\r\\n\\t]+", " ");
                        InternetAddress[] addresses = InternetAddress.parse(from);
                        if (addresses == null || addresses.length == 0) {
                            from = null;
                        } else {
                            InternetAddress address = addresses[0];
                            String fromAddress = address.getAddress().toLowerCase();
                            String personal = Core.tryToDecodeMIME(address.getPersonal());
                            if (isValidEmail(fromAddress)) {
                                from = fromAddress;
                                if (personal != null && !personal.isEmpty()) {
                                    try {
                                        if (personal.contains("@")) {
                                            personal = personal.replaceAll("[\\s\\r\\n\\t]+", " ");
                                            addresses = InternetAddress.parse(personal);
                                            if (addresses != null && addresses.length > 0) {
                                                address = addresses[0];
                                                personal = address.getAddress().toLowerCase();
                                                if (!personal.equals(from)) {
                                                    forgedFrom = true;
                                                }
                                                if (recipientSet != null && signerSet != null) {
                                                    for (String recipient : recipientSet) {
                                                        if (personal.equals(recipient)) {
                                                            if (!Filterable.isSigned(qualifier, sender, fqdn, from, signerSet)) {
                                                                spoofedRecipient = true;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        } else if (recipientSet != null && signerSet != null) {
                                            for (String recipient : recipientSet) {
                                                int index = recipient.indexOf('@');
                                                String host = recipient.substring(index + 1);
                                                String domain = Domain.normalizeHostname(host, false);
                                                if (personal.contains(domain)) {
                                                    if (!Filterable.isSigned(qualifier, sender, fqdn, from, signerSet)) {
                                                        spoofedRecipient = true;
                                                    }
                                                }
                                            }
                                        }
                                    } catch (AddressException ex) {
                                        // Do nothing.
                                    }
                                }
                            } else {
                                from = null;
                            }
                        }
                    } catch (AddressException ex) {
                        from = null;
                    }
                }
                if (replyTo == null || replyTo.length() == 0) {
                    replyTo = null;
                } else {
                    replyTo = Domain.normalizeEmail(replyTo);
                }
                if (subject == null) {
                    return null;
                } else if ((subject = Core.tryToDecodeMIME(subject)) != null) {
                    subject = subject.replaceAll("[\\s\\r\\n\\t]+", " ").trim();
                    subject = subject.isEmpty() ? null : Dictionary.normalizeCharset(subject);
                }
                subject = Dictionary.normalizeCharacters(subject);
                if (messageID == null) {
                    return null;
                } else if (messageID.length() == 0) {
                    messageID = null;
                } else {
                    int index = messageID.indexOf('<');
                    if (index >= 0) {
                        messageID = messageID.substring(index + 1);
                        index = messageID.indexOf('>');
                        if (index > 0) {
                            messageID = messageID.substring(0, index);
                        }
                    }
                }
                Date date;
                if (dateString == null) {
                    date = null;
                } else if (dateString.length() == 0) {
                    date = null;
                } else {
                    Date newDate = Core.parseEmailDateSafe(dateString);
                    if (newDate == null) {
                        date = null;
                    } else {
                        date = new Date(newDate.getTime());
                    }
                }
                URL unsubscribe = null;
                if (unsubscribeString != null && unsubscribeString.length() > 0) {
                    try {
                        int index = unsubscribeString.indexOf('<');
                        if (index >= 0) {
                            unsubscribeString = unsubscribeString.substring(index + 1);
                            index = unsubscribeString.indexOf('>');
                            if (index > 0) {
                                unsubscribeString = unsubscribeString.substring(0, index);
                                unsubscribe = new URL(unsubscribeString);
                            }
                        }
                    } catch (MalformedURLException ex) {
                        Server.logTrace("malformed unsubscribe URL: " + unsubscribeString);
                    } catch (Exception ex) {
                        Server.logError(ex);
                    }
                }
                return new Message(
                        client, ip, helo, fqdn, sender, qualifier,
                        from, replyTo, subject, messageID,
                        inReplyTo, queueID, date, unsubscribe,
                        recipientSet, signerSet, linkSet,
                        executableSet, malware,
                        forgedFrom, spoofedRecipient
                );
            } catch (Exception ex) {
                Server.logError(ex);
                return null;
            }
        }
    }
    
    private Message newMessage(
            long timeKey, String client, String ip, String helo, String fqdn,
            String sender, Qualifier qualifier, String from, String replyTo,
            String subject, String messageID, String inReplyTo,
            String queueID, Date date, URL unsubscribe,
            TreeSet<String> recipientSet, TreeSet<String> signerSet,
            TreeSet<String> linkSet, TreeSet<String> executableSet,
            String malware, boolean forgedFrom, boolean spoofedRecipient,
            Filter filter, Result result
    ) {
        return new Message(
                timeKey, client, ip, helo, fqdn, sender, qualifier,
                from, replyTo, subject, messageID,
                inReplyTo, queueID, date, unsubscribe,
                recipientSet, signerSet, linkSet,
                executableSet, malware,
                forgedFrom, spoofedRecipient,
                filter, result
        );
    }
    
    public enum Result {
        pass,
        fail,
        softfail,
        neutral,
        permerror,
        temperror,
        none,
        accept,
        junk,
        reject,
        defer
    }
    
    public static Tuple loadLicence(String encrypted) {
        if (encrypted == null) {
            return null;
        } else {
            try {
                byte[] byteArray = Server.decryptToByteArrayURLSafe(encrypted);
                return loadLicenceV1(byteArray);
            } catch (Exception ex) {
                return null;
            }
        }
    }
    
    public final static class Tuple {
        
        private final Licence licence;
        private final String client;
        private final long expiration;
        
        private Tuple(Licence licence, String client, long expiration) {
            this.licence = licence;
            this.client = client;
            this.expiration = expiration;
        }
        
        public String getUserEmail() {
            return licence.getUserEmail();
        }
        
        public String consumeAndGetUserEmail(InetAddress address) {
            if (!licence.consume()) {
                return null;
            } else if (System.currentTimeMillis() > expiration) {
                return null;
            } else if (isValidClient(address)) {
                return licence.getUserEmail();
            } else {
                return null;
            }
        }
        
        public boolean isValidClient(InetAddress address) {
            if (FQDN.isFQDN(address, client)) {
                return true;
            } else {
                return FQDN.addFQDN(address, client, true);
            }
        }
        
        public boolean isWithoutFuel() {
            return licence.isWithoutFuel();
        }
        
        public Licence getLicence() {
            return licence;
        }
        
        public Locale getLocale() {
            return licence.locale;
        }
        
        public String getClient() {
            return client;
        }
        
        public long getExpiration() {
            return expiration;
        }
        
        public boolean isExpired() {
            return System.currentTimeMillis() > expiration;
        }
        
        public Message newMessage(HashMap<String,Object> parameterMap) {
            return licence.newMessage(client, parameterMap);
        }
    }
    
    public static Tuple loadLicenceV1(byte[] byteArray) throws Exception {
        if (byteArray == null) {
            return null;
        } else {
            final long serialVersionUID = 1L;
            ByteArrayInputStream bais = new ByteArrayInputStream(byteArray);
            try (GZIPInputStream gzis = new GZIPInputStream(bais)) {
                try (DataInputStream dis =  new DataInputStream(gzis)) {
                    int hashCode1 = dis.readInt();
                    String email = Core.readUTF(dis);
                    String client = Core.readUTF(dis);
                    long expiration = dis.readLong();
                    int hashCode2 = Objects.hash(
                            "Licence", serialVersionUID, email,
                            client, expiration
                    );
                    if (!isValidEmail(email)) {
                        throw new Exception("corrupted licence data.");
                    } else if (!isHostname(client)) {
                        throw new Exception("corrupted licence data.");
                    } else if (hashCode1 != hashCode2) {
                        throw new Exception("corrupted licence data.");
                    } else {
                        Licence licence = Licence.getLicence(email);
                        return new Tuple(licence, client, expiration);
                    }
                }
            }
        }
    }
    
    public static Message loadMessage(String encrypted) {
        if (encrypted == null) {
            return null;
        } else {
            try {
                byte[] byteArray = Server.decryptToByteArrayURLSafe(encrypted);
                return loadMessageV1(byteArray);
            } catch (Exception ex) {
                return null;
            }
        }
    }
    
    public static Message loadMessageV1(byte[] byteArray) throws Exception {
        if (byteArray == null) {
            return null;
        } else {
            final long serialVersionUID = 1L;
            ByteArrayInputStream bais = new ByteArrayInputStream(byteArray);
            try (GZIPInputStream gzis = new GZIPInputStream(bais)) {
                try (DataInputStream dis =  new DataInputStream(gzis)) {
                    int hashCode1 = dis.readInt();
                    TreeSet<String> elementSet = Core.readTinySetUTF(dis);
                    String email = Core.readElement(dis, elementSet);
                    long timeKey = dis.readLong();
                    String client = Core.readElement(dis, elementSet);
                    String ip = Core.readIP(dis);
                    String helo = Core.readElement(dis, elementSet);
                    String fqdn = Core.readElement(dis, elementSet);
                    String sender = Core.readElement(dis, elementSet);
                    Qualifier qualifier = (Qualifier) Core.readEnum(dis, Qualifier.class);
                    boolean[] b1 = Core.readBooleanArray(dis);
                    boolean[] b2 = Core.readBooleanArray(dis);
                    String from = b1[0] ? Core.readElement(dis, elementSet) : null;
                    String replyTo = b1[1] ? Core.readElement(dis, elementSet) : null;
                    String subject = b1[2] ? Core.readUTF(dis) : null;
                    String messageID = b1[3] ? Core.readUTF(dis) : null;
                    String inReplyTo = b1[4] ? Core.readElement(dis, elementSet) : null;
                    String queueID = b1[5] ? Core.readUTF(dis) : null;
                    Date date = b1[6] ? Core.readDate(dis) : null;
                    URL unsubscribe = b1[7] ? Core.readURL(dis) : null;
                    TreeSet<String> recipientSet = b2[0] ? Core.readTinySetUTF(dis, elementSet) : null;
                    TreeSet<String> signerSet = b2[1] ? Core.readTinySetUTF(dis, elementSet) : null;
                    TreeSet<String> linkSet = b2[2] ? Core.readTinySetUTF(dis, elementSet) : null;
                    TreeSet<String> executableSet = b2[3] ? Core.readTinySetUTF(dis) : null;
                    String malware = b2[4] ? Core.readUTF(dis) : null;
                    Filter filter = b2[5] ? (Filter) Core.readEnum(dis, Filter.class) : null;
                    Result result = (Result) Core.readEnum(dis, Result.class);
                    boolean forgedFrom = b2[6];
                    boolean spoofedRecipient = b2[7];
                    int hashCode2 = Objects.hash(
                            "Licence", email, "Query", serialVersionUID,
                            timeKey, client, ip, helo, fqdn, sender, qualifier,
                            from, replyTo, subject, messageID,
                            inReplyTo, queueID, date, unsubscribe,
                            recipientSet, signerSet, linkSet, executableSet,
                            malware, filter, result,
                            forgedFrom, spoofedRecipient
                    );
                    if (!isValidEmail(email)) {
                        throw new Exception("corrupted licence query data.");
                    } else if (!isHostname(client)) {
                        throw new Exception("corrupted licence query data.");
                    } else if (!isValidIP(ip)) {
                        throw new Exception("corrupted licence query data.");
                    } else if (fqdn != null && !isHostname(fqdn)) {
                        throw new Exception("corrupted licence query data.");
                    } else if (sender != null && !Domain.isMailFrom(sender)) {
                        throw new Exception("corrupted licence query data.");
                    } else if (from != null && !isValidEmail(from)) {
                        throw new Exception("corrupted licence query data.");
                    } else if (replyTo != null && !isValidEmail(replyTo)) {
                        throw new Exception("corrupted licence query data.");
                    } else if (hashCode1 != hashCode2) {
                        throw new Exception("corrupted licence query data.");
                    } else {
                        Licence licence = new Licence(email);
                        return licence.newMessage(
                                timeKey, client, ip, helo, fqdn,
                                sender, qualifier, from, replyTo,
                                subject, messageID, inReplyTo,
                                queueID, date, unsubscribe,
                                recipientSet, signerSet,
                                linkSet, executableSet,
                                malware, forgedFrom, spoofedRecipient,
                                filter, result
                        );
                    }
                }
            }
        }
    }
    
    public final class Message extends Filterable {
        
        private static final long serialVersionUID = 1L;

        private final long timeKey;
        private final String client;
        private final String ip;
        private final String helo;
        private final String fqdn;
        private final String sender;
        private final Qualifier qualifier;
        
        private final String from;
        private final String replyTo;
        private final String subject;
        private final String messageID;
        private final String inReplyTo;
        private final String queueID;
        private final Date date;
        private final URL unsubscribe;
        
        private final TreeSet<String> recipientSet;
        private final TreeSet<String> signerSet;
        private final TreeSet<String> linkSet;
        private final TreeSet<String> executableSet;
        private final String malware;
        
        private final Filter filter;
        private final Result result;
        
        private final boolean forgedFrom;
        private final boolean spoofedRecipient;
        
        private Message(
                String client,
                String ip,
                String helo,
                String fqdn,
                String sender,
                Qualifier qualifier,
                String from,
                String replyTo,
                String subject,
                String messageID,
                String inReplyTo,
                String queueID,
                Date date,
                URL unsubscribe,
                TreeSet<String> recipientSet,
                TreeSet<String> signerSet,
                TreeSet<String> linkSet,
                TreeSet<String> executableSet,
                String malware,
                boolean forgedFrom,
                boolean spoofedRecipient
        ) {
            this.timeKey = Server.getNewUniqueTime();
            this.client = client;
            this.ip = ip;
            this.helo = helo;
            this.fqdn = fqdn;
            this.sender = sender;
            this.qualifier = qualifier;
            this.from = from;
            this.replyTo = replyTo;
            this.subject = subject;
            this.messageID = messageID;
            this.inReplyTo = inReplyTo;
            this.queueID = queueID;
            this.date = date;
            this.unsubscribe = unsubscribe;
            this.recipientSet = recipientSet;
            this.signerSet = signerSet;
            this.linkSet = linkSet;
            this.executableSet = executableSet;
            this.malware = malware;
            this.forgedFrom = forgedFrom;
            this.spoofedRecipient = spoofedRecipient;
            this.filter = processFilter();
            this.result = processResult();
        }
        
        private Message(
                long timeKey,
                String client,
                String ip,
                String helo,
                String fqdn,
                String sender,
                Qualifier qualifier,
                String from,
                String replyTo,
                String subject,
                String messageID,
                String inReplyTo,
                String queueID,
                Date date,
                URL unsubscribe,
                TreeSet<String> recipientSet,
                TreeSet<String> signerSet,
                TreeSet<String> linkSet,
                TreeSet<String> executableSet,
                String malware,
                boolean forgedFrom,
                boolean spoofedRecipient,
                Filter filter,
                Result result
        ) {
            this.timeKey = timeKey;
            this.client = client;
            this.ip = ip;
            this.helo = helo;
            this.fqdn = fqdn;
            this.sender = sender;
            this.qualifier = qualifier;
            this.from = from;
            this.replyTo = replyTo;
            this.subject = subject;
            this.messageID = messageID;
            this.inReplyTo = inReplyTo;
            this.queueID = queueID;
            this.date = date;
            this.unsubscribe = unsubscribe;
            this.recipientSet = recipientSet;
            this.signerSet = signerSet;
            this.linkSet = linkSet;
            this.executableSet = executableSet;
            this.malware = malware;
            this.forgedFrom = forgedFrom;
            this.spoofedRecipient = spoofedRecipient;
            this.filter = filter;
            this.result = result;
        }
        
        @Override
        public int hashCode() {
            return Objects.hash("Licence", email, "Query", Message.serialVersionUID,
                    timeKey, client, ip, helo, fqdn, sender, qualifier,
                    from, replyTo, subject, messageID,
                    inReplyTo, queueID, date, unsubscribe,
                    recipientSet, signerSet, linkSet, executableSet,
                    malware, filter, result,
                    forgedFrom, spoofedRecipient
            );
        }

        @Override
        public boolean equals(Object obj) {
            if (obj instanceof Licence.Message) {
                final Message other = (Message) obj;
                return this.timeKey == other.timeKey;
            } else {
                return false;
            }
        }
        
        public byte[] getByteArray() throws Exception {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (GZIPOutputStream gzos = new GZIPOutputStream(baos)) {
                try (DataOutputStream dos =  new DataOutputStream(gzos)) {
                    dos.writeInt(hashCode());
                    TreeSet<String> elementSet = new TreeSet<>();
                    elementSet.add(email);
                    elementSet.add(client);
                    elementSet.add(helo);
                    if (fqdn != null) {
                        elementSet.add(fqdn);
                    }
                    if (sender != null) {
                        elementSet.add(sender);
                    }
                    if (recipientSet != null) {
                        elementSet.addAll(recipientSet);
                    }
                    if (signerSet != null) {
                        elementSet.addAll(signerSet);
                    }
                    if (from != null) {
                        elementSet.add(from);
                    }
                    if (replyTo != null) {
                        elementSet.add(replyTo);
                    }
                    if (linkSet != null) {
                        elementSet.addAll(linkSet);
                    }
                    Core.writeTinyUTF(dos, elementSet);                    
                    Core.writeTinyElement(dos, elementSet, email);
                    dos.writeLong(timeKey);
                    Core.writeTinyElement(dos, elementSet, client);
                    Core.writeIP(dos, ip);
                    Core.writeTinyElement(dos, elementSet, helo);
                    Core.writeTinyElement(dos, elementSet, fqdn);
                    Core.writeTinyElement(dos, elementSet, sender);
                    Core.writeEnum(dos, qualifier);
                    Core.writeBooleanArray(
                            dos,
                            from != null,
                            replyTo != null,
                            subject != null,
                            messageID != null,
                            inReplyTo != null,
                            queueID != null,
                            date != null,
                            unsubscribe != null
                    );
                    Core.writeBooleanArray(
                            dos,
                            recipientSet != null,
                            signerSet != null,
                            linkSet != null,
                            executableSet != null,
                            malware != null,
                            filter != null,
                            forgedFrom,
                            spoofedRecipient
                    );
                    if (from != null) {
                        Core.writeTinyElement(dos, elementSet, from);
                    }
                    if (replyTo != null) {
                        Core.writeTinyElement(dos, elementSet, replyTo);
                    }
                    if (subject != null) {
                        Core.writeUTF(dos, subject);
                    }
                    if (messageID != null) {
                        Core.writeUTF(dos, messageID);
                    }
                    if (inReplyTo != null) {
                        Core.writeTinyElement(dos, elementSet, inReplyTo);
                    }
                    if (queueID != null) {
                        Core.writeUTF(dos, queueID);
                    }
                    if (date != null) {
                        Core.writeDate(dos, date);
                    }
                    if (unsubscribe != null) {
                        Core.writeURL(dos, unsubscribe);
                    }
                    if (recipientSet != null) {
                        Core.writeTinySubset(dos, elementSet, recipientSet);
                    }
                    if (signerSet != null) {
                        Core.writeTinySubset(dos, elementSet, signerSet);
                    }
                    if (linkSet != null) {
                        Core.writeTinySubset(dos, elementSet, linkSet);
                    }
                    if (executableSet != null) {
                        Core.writeTinyUTF(dos, executableSet);
                    }
                    if (malware != null) {
                        Core.writeUTF(dos, malware);
                    }
                    if (filter != null) {
                        Core.writeEnum(dos, filter);
                    }
                    Core.writeEnum(dos, result);
                }
            }
            return baos.toByteArray();
        }
        
        public String getQueryID() {
            return '#' + Long.toString(timeKey, 32);
        }
        
        @Override
        public String getUserEmail() {
            return email;
        }

        @Override
        public String getClient() {
            return client;
        }
        
        public String getClient(InetAddress inetAddress) {
            if (inetAddress == null) {
                return null;
            } else if (FQDN.isFQDN(inetAddress.getHostAddress(), client)) {
                return client;
            } else {
                return null;
            }
        }

        @Override
        public String getIP() {
            return ip;
        }

        @Override
        public String getHELO() {
            return helo;
        }

        @Override
        public String getFQDN() {
            return fqdn;
        }

        @Override
        public String getSender() {
            return sender;
        }
        
        @Override
        public Qualifier getQualifier() {
            return qualifier;
        }

        @Override
        public TreeSet<String> getRecipientSet() {
            return recipientSet;
        }

        @Override
        public String getFrom() {
            return from;
        }

        @Override
        public String getReplyTo() {
            return replyTo;
        }
        
        @Override
        public String getMessageID() {
            return messageID;
        }
        
        @Override
        public String getQueueID() {
            return queueID;
        }

        @Override
        public Date getDate() {
            return date;
        }

        @Override
        public URL getUnsubscribe() {
            return unsubscribe;
        }
        @Override
        public String getInReplyTo() {
            return inReplyTo;
        }

        @Override
        public String getSubject() {
            return subject;
        }

        @Override
        public Locale getLocale() {
            return locale;
        }
        
        @Override
        public boolean isFilter(Filter... filterArray) {
            if (filterArray == null) {
                return false;
            } else {
                for (Filter filter : filterArray) {
                    if (this.filter == filter) {
                        return true;
                    }
                }
                return false;
            }
        }

        @Override
        public String getMalware() {
            return malware;
        }

        @Override
        public TreeSet<String> getExecutableSet() {
            return executableSet;
        }

        @Override
        public TreeSet<String> getSignerSet() {
            return signerSet;
        }

        @Override
        public TreeSet<String> getLinkSet() {
            return linkSet;
        }

        @Override
        public boolean isInvitation() {
            return false;
        }
        
        @Override
        public boolean isForgedFrom() {
            return forgedFrom;
        }
        
        @Override
        public boolean isSpoofedRecipient() {
            return spoofedRecipient;
        }
        
        public Filter getFilter() {
            return filter;
        }
        
        public Result getResult() {
            return result;
        }
        
        public String consumeAndGetUserEmail() {
            if (consume()) {
                return getUserEmail();
            } else {
                return null;
            }
        }
        
        public boolean write(JSONObject json) {
            if (json == null) {
                return false;
            } else {
                json.put("userEmail", email);
                json.put("timeKey", timeKey);
                json.put("client", client);
                json.put("ip", ip);
                json.put("helo", helo);
                json.put("fqdn", fqdn);
                json.put("sender", sender);
                json.put("qualifier", qualifier);
                json.put("from", from);
                json.put("replyTo", replyTo);
                json.put("subject", subject);
                json.put("messageID", messageID);
                json.put("inReplyTo", inReplyTo);
                json.put("queueID", queueID);
                json.put("date", date);
                json.put("unsubscribe", unsubscribe);
                json.put("recipientSet", recipientSet);
                json.put("signerSet", signerSet);
                json.put("linkSet", linkSet);
                json.put("executableSet", executableSet);
                json.put("malware", malware);
                json.put("filter", filter);
                json.put("result", result);
                json.put("forgedFrom", forgedFrom);
                json.put("spoofedRecipient", spoofedRecipient);
                json.put("abuseEmail", getAbuseSender());
                return true;
            }
        }
        
        public String getMessageURL() {
            try {
                byte[] byteArray = getByteArray();
                String encrypted = Server.encryptURLSafe(byteArray);
                String command = "message/" + encrypted;
                return Core.getURL(true, null, command);
            } catch (Exception ex) {
                Server.logError(ex);
                return null;
            }
        }
        
        public String getInformation() {
            if (filter != null) {
                switch (filter) {
                    case RECIPIENT_INEXISTENT:
                        return "non-existent recipient";
                    case RECIPIENT_POSTMASTER:
                        return "message to postmaster";
                    case RECIPIENT_ABUSE:
                        return "message to abuse";
                    case RECIPIENT_HACKED:
                        return "bounce to hacked recipient";
                    case IN_REPLY_TO_EXISTENT:
                        return "reply message";
                    case IN_REPLY_TO_DESIRABLE:
                        return "trusted reply message";
                    case ORIGIN_WHITE_KEY_USER:
                        return "whitelisted by user";
                    case ORIGIN_WHITE_KEY_ADMIN:
                        return "whitelisted by admin";
                    case ORIGIN_WHITELISTED:
                        return "whitelisted by system";
                    case CIDR_BENEFICIAL:
                        return "reputable range";
                    case SPF_BENEFICIAL:
                        return "reputable sender";
                    case FQDN_BENEFICIAL:
                        return "reputable server";
                    case DKIM_BENEFICIAL:
                        return "reputable from";
                    case BULK_BENEFICIAL:
                        return "reputable bulk";
                    case BULK_BOUNCE:
                        return "bounce from bulk";
                    case ABUSE_BENEFICIAL:
                        return "reputable abuse";
                    case SENDER_MAILER_DEAMON:
                        return "bounce message";
                    case SENDER_MAILER_DEAMON_TRUSTED:
                        return "trusted bounce message";
                    case SPF_DESIRABLE:
                        return "trusted sender";
                    case DKIM_DESIRABLE:
                        return "trusted from";
                    case FQDN_DESIRABLE:
                        return "trusted server";
                    case CIDR_HARMFUL:
                        return "disreputable range";
                    case FQDN_HARMFUL:
                        return "disreputable server";
                    case SPF_HARMFUL:
                        return "disreputable sender";
                    case DKIM_HARMFUL:
                        return "disreputable from";
                    case ABUSE_HARMFUL:
                        return "disreputable abuse";
                    case FROM_ABSENT:
                        return "from absent";
                    case FROM_NOT_SIGNED:
                        return "from not signed";
                    case FROM_FREEMAIL:
                        return "from not signed freemail";
                    case SPF_FAIL:
                        return "SPF failed";
                    case SPF_SPOOFING:
                        return "SPF spoofed";
                    case FQDN_SPOOFED:
                        return "FQDN spoofed";
                    case FROM_SPOOFED_SENDER:
                        return "from spoofed";
                    case SENDER_SPOOFING:
                        return "sender spoofed";
                    case EXECUTABLE_BLOCKED:
                        return "executable blocked";
                    case SUBJECT_BENEFICIAL:
                        return "reputable subject";
                    case SUBJECT_HARMFUL:
                        return "disreputable subject";
                    case FROM_BLOCKED:
                        return "blocked from";
                    case FROM_UNROUTABLE:
                        return "unroutable from";
                    case MALWARE_NOT_IGNORED:
                        return "malware found";
                    case FROM_NXDOMAIN:
                        return "non-existent from";
                    case SENDER_NXDOMAIN:
                        return "non-existent sender";
                    case FROM_SUSPECT:
                        return "suspect from";
                    case PHISHING_BLOCKED:
                        return "phishing found";
                    case FROM_FORGED:
                        return "forged from";
                    case ORIGIN_BLOCK_KEY_USER:
                        return "sender blocked by user";
                    case ORIGIN_BLOCK_KEY_ADMIN:
                        return "sender blocked by admin";
                    case FROM_SPOOFED_RECIPIENT:
                        return "from spoofing recipient";
                    case EXECUTABLE_UNDESIRABLE:
                        return "executable from disreputable";
                    case HREF_UNDESIRABLE:
                         return "suspect link from disreputable";
                    case IP_DYNAMIC:
                         return "dynamic IP";
                    case HELO_ANONYMOUS:
                        return "anonymous HELO";
                    case ORIGIN_BANNED:
                         return "banned origin";
                    case EXECUTABLE_NOT_IGNORED:
                         return "executable found";
                    case HREF_SUSPECT:
                         return "suspect link";
                    case ORIGIN_BLOCKED:
                         return "blocked origin";
                    case SUBJECT_UNDESIRABLE:
                        return "suspect subject";
                    case SENDER_RED:
                        return "bad reputation sender";
                    case FQDN_RED:
                        return "bad reputation server";
                    case DOMAIN_EMERGED:
                        return "emergent domain";
                    case DOMAIN_INEXISTENT:
                        return "inexistent domain";
                    case SPF_UNDESIRABLE:
                        return "suspect sender";
                    case FQDN_UNDESIRABLE:
                        return "suspect server";
                    case SENDER_INVALID:
                        return "invalid sender";
                    case SPF_SOFTFAIL:
                        return "SPF failed softly";
                    case RECIPIENT_HARMFUL:
                        return "disreputable recipient";
                    case RECIPIENT_PRIVATE:
                        return "private recipient";
                    case RECIPIENT_RESTRICT:
                        return "restrict recipient";
                    case RECIPIENT_BENEFICIAL:
                        return "reputable recipient";
                    case RECIPIENT_DESIRABLE:
                        return "trusted recipient";
                    case RECIPIENT_UNDESIRABLE:
                        return "suspect recipient";
                    case DKIM_UNDESIRABLE:
                        return "suspect from";
                    case ENVELOPE_BLOCKED:
                        return "envelope blocked";
                    case ENVELOPE_INVALID:
                        return "envelope invalid";
                    case ENVELOPE_UNDESIRABLE:
                        return "suspect envelope";
                    case RECIPIENT_SPOOFING:
                        return "spoofed recipient";
                    case ENVELOPE_HARMFUL:
                        return "disreputable envelope";
                    case ENVELOPE_BENEFICIAL:
                        return "reputable envelope";
                    case ENVELOPE_DESIRABLE:
                        return "desirable envelope";
                    case FQDN_PROVIDER:
                        return "message from bulk";
                    case ORIGIN_UNDESIRABLE:
                        return "suspected origin";
                    case ABUSE_BLOCKED:
                        return "abuse blocked";
                    case SUBJECT_DESIRABLE:
                        return "desirable subject";
                    case FROM_ESSENTIAL:
                        return "essential from";
                    case SENDER_ESSENTIAL:
                        return "essential sender";
                    case FQDN_ESSENTIAL:
                        return "essential FQDN";
                    default:
                        Server.logError("undefined filter: " + filter.name());
                }
            }
            if (sender == null) {
                return "bulk message";
            } else if (qualifier == null) {
                return "no valid SPF registry";
            } else if (qualifier == Qualifier.PASS) {
                return "designates " + ip + " as permitted sender";
            } else {
                return "does not designate " + ip + " as permitted sender";
            }
        }
                
        private Result processResult() {
            if (filter != null) {
                switch (filter) {
                    case ORIGIN_WHITE_KEY_USER:
                    case ORIGIN_WHITE_KEY_ADMIN:
                    case ORIGIN_WHITELISTED:
                    case SPF_BENEFICIAL:
                    case FQDN_BENEFICIAL:
                    case DKIM_BENEFICIAL:
                    case BULK_BENEFICIAL:
                    case BULK_BOUNCE:
                    case ABUSE_BENEFICIAL:
                    case RECIPIENT_ABUSE:
                    case RECIPIENT_HACKED:
                    case RECIPIENT_POSTMASTER:
                    case SENDER_MAILER_DEAMON:
                    case SENDER_MAILER_DEAMON_TRUSTED:
                    case IN_REPLY_TO_EXISTENT:
                    case IN_REPLY_TO_DESIRABLE:
                    case CIDR_BENEFICIAL:
                    case SUBJECT_BENEFICIAL:
                    case SPF_DESIRABLE:
                    case DKIM_DESIRABLE:
                    case FQDN_DESIRABLE:
                    case RECIPIENT_BENEFICIAL:
                    case RECIPIENT_DESIRABLE:
                    case FQDN_PROVIDER:
                    case SUBJECT_DESIRABLE:
                    case FROM_ESSENTIAL:
                    case SENDER_ESSENTIAL:
                    case FQDN_ESSENTIAL:
                    case ENVELOPE_BENEFICIAL:
                    case ENVELOPE_DESIRABLE:
                        return Result.accept;
                    case DKIM_HARMFUL:
                    case FROM_ABSENT:
                    case RECIPIENT_INEXISTENT:
                    case FROM_NOT_SIGNED:
                    case SPF_FAIL:
                    case SPF_SPOOFING:
                    case FQDN_SPOOFED:
                    case FROM_SPOOFED_SENDER:
                    case EXECUTABLE_BLOCKED:
                    case SUBJECT_HARMFUL:
                    case MALWARE_NOT_IGNORED:
                    case FROM_NXDOMAIN:
                    case SENDER_NXDOMAIN:
                    case FROM_SUSPECT:
                    case PHISHING_BLOCKED:
                    case FROM_FORGED:
                    case ORIGIN_BLOCK_KEY_USER:
                    case ORIGIN_BLOCK_KEY_ADMIN:
                    case FROM_SPOOFED_RECIPIENT:
                    case EXECUTABLE_UNDESIRABLE:
                    case HREF_UNDESIRABLE:
                    case IP_DYNAMIC:
                    case HELO_ANONYMOUS:
                    case ORIGIN_BANNED:
                    case ABUSE_HARMFUL:
                    case ORIGIN_UNDESIRABLE:
                    case ABUSE_BLOCKED:
                    case RECIPIENT_PRIVATE:
                    case ENVELOPE_HARMFUL:
                    case RECIPIENT_SPOOFING:
                    case SENDER_SPOOFING:
                    case DOMAIN_INEXISTENT:
                        return Result.reject;
                    case EXECUTABLE_NOT_IGNORED:
                    case HREF_SUSPECT:
                    case ORIGIN_BLOCKED:
                    case SUBJECT_UNDESIRABLE:
                    case CIDR_HARMFUL:
                    case FQDN_HARMFUL:
                    case SPF_HARMFUL:
                    case SENDER_RED:
                    case FQDN_RED:
                    case SPF_UNDESIRABLE:
                    case FQDN_UNDESIRABLE:
                    case SENDER_INVALID:
                    case FROM_UNROUTABLE:
                    case FROM_BLOCKED:
                    case FROM_FREEMAIL:
                    case RECIPIENT_HARMFUL:
                    case RECIPIENT_UNDESIRABLE:
                    case ENVELOPE_BLOCKED:
                    case ENVELOPE_INVALID:
                    case ENVELOPE_UNDESIRABLE:
                        return Result.junk;
                    case DOMAIN_EMERGED:
                    case SPF_SOFTFAIL:
                    case RECIPIENT_RESTRICT:
                        if (Defer.deferSOFTFAIL(getFlow())) {
                            return Result.defer;
                        } else {
                            return Result.accept;
                        }
                    default:
                        Server.logError("undefined filter: " + filter.name());
                }
            }
            if (qualifier == null) {
                return Result.none;
            } else {
                switch (qualifier) {
                    case PASS:
                        return Result.pass;
                    case FAIL:
                        return Result.fail;
                    case SOFTFAIL:
                        return Result.softfail;
                    case NEUTRAL:
                        return Result.neutral;
                    default:
                        return Result.none;
                }
            }
        }
    }
}
