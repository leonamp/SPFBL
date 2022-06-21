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

import net.spfbl.core.Client;
import com.sun.mail.dsn.DispositionNotification;
import com.sun.mail.dsn.MultipartReport;
import com.sun.mail.smtp.SMTPAddressFailedException;
import com.sun.mail.util.MailConnectException;
import com.sun.mail.util.SocketConnectException;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.SendFailedException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.InternetHeaders;
import javax.mail.internet.MimeMessage;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.ServiceUnavailableException;
import net.spfbl.core.Core;
import net.spfbl.core.Defer;
import net.spfbl.core.Filterable.Filter;
import net.spfbl.core.ProcessException;
import static net.spfbl.core.Regex.isHostname;
import static net.spfbl.core.Regex.isValidCIDR;
import static net.spfbl.core.Regex.isValidEmail;
import static net.spfbl.core.Regex.isValidIPv4;
import static net.spfbl.core.Regex.isValidIPv6;
import net.spfbl.core.Reverse;
import net.spfbl.core.Server;
import net.spfbl.core.User;
import net.spfbl.data.Reputation.Flag;
import static net.spfbl.data.Reputation.Flag.ACCEPTABLE;
import static net.spfbl.data.Reputation.Flag.BENEFICIAL;
import static net.spfbl.data.Reputation.Flag.DESIRABLE;
import static net.spfbl.data.Reputation.Flag.HARMFUL;
import static net.spfbl.data.Reputation.Flag.UNACCEPTABLE;
import static net.spfbl.data.Reputation.Flag.UNDESIRABLE;
import net.spfbl.service.ServerSMTP;
import net.spfbl.spf.SPF.Qualifier;
import static net.spfbl.spf.SPF.Qualifier.PASS;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv4;
import net.spfbl.whois.SubnetIPv6;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Representa a lista de responsáveis por abusos de cada domínio.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Abuse {
    
    /**
     * Conjunto de responsáveis por abusos de cada domínio.
     */
    private static final HashMap<String,String> MAP = new HashMap<>();
    
    private static boolean dropExact(String domain) {
        if (removeMap(domain)) {
            append("DROP " + domain);
            return true;
        } else {
            return false;
        }
    }

    private synchronized static boolean removeMap(String domain) {
        if (domain == null) {
            return false;
        } else if (MAP.remove(domain) == null) {
            return false;
        } else {
            return true;
        }
    }
    
    public static String getExact(String address) {
        return MAP.get(address);
    }
    
    private static boolean putExact(String address, String email) {
        if (putMap(address, email)) {
            append("PUT " + address + " " + email);
            return true;
        } else {
            return false;
        }
    }
    
    private synchronized static boolean putMap(String address, String email) {
        if (address == null || email == null) {
            return false;
        } else {
            String addressOld = MAP.put(address, email);
            if (addressOld == null) {
                return true;
            } else if (addressOld.equals(email)) {
                return false;
            } else {
                return true;
            }
        }
    }

    public synchronized static TreeSet<String> getKeySet() {
        TreeSet<String> domainSet = new TreeSet<>();
        domainSet.addAll(MAP.keySet());
        return domainSet;
    }
    
    public static TreeSet<String> dropAll() {
        TreeSet<String> domainSet = new TreeSet<>();
        for (String address : getKeySet()) {
            if (dropExact(address)) { 
               domainSet.add(address);
            }
        }
        return domainSet;
    }
    
    private static String normalizeAddress(String token) {
        if (isValidIPv4(token)) {
            return SubnetIPv4.normalizeCIDRv4(token + "/32");
        } else if (isValidIPv6(token)) {
            return SubnetIPv6.normalizeCIDRv6(token + "/128");
        } else if (isValidCIDR(token)) {
            return Subnet.normalizeCIDR(token);
        } else if (isHostname(token)) {
            return Domain.normalizeHostname(token, true);
        } else {
            return null;
        }
    }
    
    public static boolean putSafe(String address, String email) {
        try {
            return put(address, email);
        } catch (ProcessException ex) {
            Server.logError(ex);
            return false;
        }
    }
    
    public static boolean put(String address, String email) throws ProcessException {
        if ((email = Domain.normalizeEmail(email)) == null) {
            throw new ProcessException("INVALID EMAIL");
        } else if ((address = normalizeAddress(address)) == null) {
            throw new ProcessException("INVALID ADDRESS");
        } else if (!isValidEmail(email = email.toLowerCase())) {
            throw new ProcessException("INVALID EMAIL");
        } else if (Core.isMatrixDefence()) {
            return putExact(address, email);
        } else {
            return false;
        }
    }
    
    private static final String DNSAL = "abuse.spfbl.net";
    
    public static String getEmailFqdnOrIP(String address) {
        if (address == null) {
            return null;
        } else if (isValidIPv4(address)) {
            return getEmailFqdnOrIPv4(address);
        } else if (isValidIPv6(address)) {
            return getEmailFqdnOrIPv6(address);
        } else {
            return null;
        }
    }
    
    public static String getEmailIP(String address) {
        if (address == null) {
            return null;
        } else if (isValidIPv4(address)) {
            return getEmailIPv4(address);
        } else if (isValidIPv6(address)) {
            return getEmailIPv6(address);
        } else {
            return null;
        }
    }
    
    public static boolean isSubscribed(String email) {
        if (email == null) {
            return false;
        } else if (NoReply.isUnsubscribed(email)) {
            return false;
        } else if (Core.isMatrixDefence()) {
            return true;
        } else {
            try {
                String result = Reverse.getAddress4(email + "." + DNSAL);
                return Objects.equals(result, "127.0.0.2");
            } catch (NamingException ex) {
                return false;
            }
        }
    }
    
    public static boolean isUnsubscribed(String email) {
        if (email == null) {
            return false;
        } else if (NoReply.isUnsubscribed(email)) {
            return true;
        } else if (Core.isMatrixDefence()) {
            return false;
        } else {
            try {
                String result = Reverse.getAddress4(email + "." + DNSAL);
                return Objects.equals(result, "127.0.0.3");
            } catch (NamingException ex) {
                return true;
            }
        }
    }
    
    public static String getEmailIPv4(String address) {
        String[] rangeArray = SubnetIPv4.getRangeArrayIPv4(address);
        if (rangeArray == null) {
            return null;
        } else if (Core.isMatrixDefence()) {
            String first = null;
            for (int index = rangeArray.length - 1; index >= 0; index--) {
                String cidr = rangeArray[index];
                String email = getExact(cidr);
                if (email != null) {
                    if (isSubscribed(email)) {
                        return email;
                    } else if (first == null) {
                        first = email;
                    }
                }
            }
            return first;
        } else {
            String reverse = SubnetIPv4.reverseIPv4(address);
            ArrayList<String> emailSet = Reverse.getTXTSetSafe(
                    reverse + "." + DNSAL
            );
            if (emailSet == null) {
                return null;
            } else {
                String first = null;
                for (String email : emailSet) {
                    if (isValidEmail(email)) {
                        if (isSubscribed(email)) {
                            return email;
                        } else if (first == null) {
                            first = email;
                        }
                    }
                }
                return first;
            }
        }
    }
    
    public static String getEmailFqdnOrIPv4(String address) {
        if (address == null) {
            return null;
        } else {
            String fqdn = FQDN.getFQDN(address, false);
            String email1 = getEmailFQDN(fqdn);
            if (isSubscribed(email1)) {
                return email1;
            }
            String email2 = getEmailIPv4(address);
            if (isSubscribed(email2)) {
                return email2;
            } else if (email1 == null) {
                email1 = email2;
            }
            return email1;
        }
    }
    
    public static String getEmailIPv6(String address) {
        String[] rangeArray = SubnetIPv6.getRangeArrayIPv6(address);
        if (rangeArray == null) {
            return null;
        } else if (Core.isMatrixDefence()) {
            String first = null;
            for (int index = rangeArray.length - 1; index >= 0; index--) {
                String cidr = rangeArray[index];
                String email = getExact(cidr);
                if (email != null) {
                    if (isSubscribed(email)) {
                        return email;
                    } else if (first == null) {
                        first = email;
                    }
                }
            }
            return first;
        } else {
            String reverse = SubnetIPv6.reverseIPv6(address);
            ArrayList<String> emailSet = Reverse.getTXTSetSafe(
                    reverse + "." + DNSAL
            );
            if (emailSet == null) {
                return null;
            } else {
                String first = null;
                for (String email : emailSet) {
                    if (isValidEmail(email)) {
                        if (isSubscribed(email)) {
                            return email;
                        } else if (first == null) {
                            first = email;
                        }
                    }
                }
                return first;
            }
        }
    }
    
    public static String getEmailFqdnOrIPv6(String address) {
        if (address == null) {
            return null;
        } else {
            String fqdn = FQDN.getFQDN(address, false);
            String email1 = getEmailFQDN(fqdn);
            if (isSubscribed(email1)) {
                return email1;
            }
            String email2 = getEmailIPv6(address);
            if (isSubscribed(email2)) {
                return email2;
            } else if (email1 == null) {
                email1 = email2;
            }
            return email1;
        }
    }
    
    private static String getEmailZone(String zone) {
        if (zone == null) {
            return null;
        } else if (Core.isMatrixDefence()) {
            return getExact(zone);
        } else {
            if (zone.startsWith(".")) {
                zone = zone.substring(1);
            }
            ArrayList<String> emailSet = Reverse.getTXTSetSafe(
                    zone + ".dnsal.spfbl.net"
            );
            if (emailSet == null) {
                return null;
            } else {
                String first = null;
                for (String email : emailSet) {
                    if (isValidEmail(email)) {
                        if (isSubscribed(email)) {
                            return email;
                        } else if (first == null) {
                            first = email;
                        }
                    }
                }
                return first;
            }
        }
    }
    
    public static String getEmailFQDN(String address) {
        if ((address = Domain.normalizeHostname(address, true)) == null) {
            return null;
        } else {
            String domain = Domain.extractDomainSafe(address, true);
            if (domain == null) {
                return getEmailZone(address);
            } else if (address.endsWith(domain)) {
                String subdominio = address;
                while (!subdominio.equals(domain)) {
                    String email = getEmailZone(subdominio);
                    if (email == null) {
                        int index = subdominio.indexOf('.', 1);
                        subdominio = subdominio.substring(index);
                    } else {
                        return email;
                    }
                }
                return getEmailZone(domain);
            } else {
                return getEmailZone(address);
            }
        }
    }
    
    public static String getEmail(String ip, String fqdn) {
        return getEmail(ip, fqdn, null, (Qualifier) null);
    }
    
    public static String getEmail(
            String ip, String fqdn,
            String sender, Qualifier qualifier
    ) {
        if (ip == null) {
            return null;
        } else if (fqdn == null) {
            return getEmailIP(ip);
        } else if (sender != null && qualifier == PASS && fqdn.endsWith(".google.com")) {
            /**
             * GSuite's abuse report rule:
             * https://support.google.com/a/answer/178266?hl=en
             */
            int index = sender.indexOf('@') + 1;
            return "abuse@" + sender.substring(index);
        } else {
            String email1 = Abuse.getEmailFQDN(fqdn);
            if (isSubscribed(email1)) {
                return email1;
            } else {
                String email2 = getEmailIP(ip);
                if (email1 == null) {
                    email1 = email2;
                }
                return email1;
            }
        }
    }
    
    public static boolean isBlocked(
            Client client, User user,
            String ip, String fqdn,
            String sender, String qualifier
    ) {
        
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        } else if (client != null) {
            userEmail = client.getEmail();
        }
        if (userEmail == null) {
            return false;
        } else {
            String abuse = Abuse.getEmail(ip, fqdn, sender, qualifier);
            return Block.containsExact(userEmail, abuse);
        }
    }
    
    public static String getEmail(
            String ip, String fqdn,
            String sender, String qualifier
    ) {
        if (ip == null) {
            return null;
        } else if (fqdn == null) {
            return getEmailIP(ip);
        } else if (sender != null && qualifier != null && qualifier.equals("PASS") && fqdn.endsWith(".google.com")) {
            /**
             * GSuite's abuse report rule:
             * https://support.google.com/a/answer/178266?hl=en
             */
            int index = sender.indexOf('@') + 1;
            return "abuse@" + sender.substring(index);
        } else {
            String email1 = Abuse.getEmailFQDN(fqdn);
            if (isSubscribed(email1)) {
                return email1;
            } else {
                String email2 = getEmailIP(ip);
                if (email1 == null) {
                    email1 = email2;
                }
                return email1;
            }
        }
    }
    
    public static String getEmail(String address) {
        if (address == null) {
            return null;
        } else if (isValidIPv4(address)) {
            return getEmailFqdnOrIPv4(address);
        } else if (isValidIPv6(address)) {
            return getEmailFqdnOrIPv6(address);
        } else if (isHostname(address)) {
            return getEmailFQDN(address);
        } else {
            return null;
        }
    }
    
    public static boolean containsSubscribedIP(String ip) {
        String fqdn;
        String cidr;
        if (isValidIPv4(ip)) {
            fqdn = FQDN.getFQDN(ip, false);
            cidr = SubnetIPv4.normalizeCIDRv4(ip + "/32");
        } else if (isValidIPv6(ip)) {
            fqdn = FQDN.getFQDN(ip, false);
            cidr = SubnetIPv6.normalizeCIDRv6(ip + "/128");
        } else {
            return false;
        }
        String email = getEmailFQDN(fqdn);
        if (email == null && Core.isMatrixDefence()) {
            email = getExact(cidr);
        }
        if (email == null) {
            return false;
        } else {
            return isSubscribed(email);
        }
    }
    
    public static boolean containsEmailCIDR(String ip, String email) {
        String[] rangeArray;
        if (email == null) {
            return false;
        } else if (!Core.isMatrixDefence()) {
            return false;
        } else if ((rangeArray = Subnet.getRangeArray(ip)) == null) {
            return false;
        } else {
            for (String cidr : rangeArray) {
                if (email.equals(getExact(cidr))) {
                    return true;
                }
            }
            return false;
        }
    }
    
    public static boolean dropAllEmail(String email) {
        if ((email = Domain.normalizeEmail(email)) == null) {
            return false;
        } else {
            boolean dropped = false;
            for (String key : getKeySet()) {
                String value = getExact(key);
                if (value != null && email.equals(value) && dropExact(key)) {
                    dropped = true;
                }
            }
            return dropped;
        }
    }
    
    public static boolean dropEmail(String address, String email) {
        if (address == null) {
            return false;
        } else if ((email = Domain.normalizeEmail(email)) == null) {
            return false;
        } else if (!Core.isMatrixDefence()) {
            return false;
        } else if (isValidIPv4(address)) {
            String fqdn = FQDN.getFQDN(address, true);
            email = email.toLowerCase();
            boolean removed = dropEmail(fqdn, email);
            for (int mask = 32; mask > 0; mask--) {
                String key = SubnetIPv4.normalizeCIDRv4(address + "/" + mask);
                String value = getExact(key);
                if (email.equals(value) && dropExact(key)) {
                    removed = true;
                }
            }
            return removed;
        } else if (isValidIPv6(address)) {
            String fqdn = FQDN.getFQDN(address, true);
            email = email.toLowerCase();
            boolean removed = dropEmail(fqdn, email);
            for (int mask = 128; mask > 0; mask--) {
                String key = SubnetIPv6.normalizeCIDRv6(address + "/" + mask);
                String value = getExact(key);
                if (email.equals(value) && dropExact(key)) {
                    removed = true;
                }
            }
            return removed;
        } else if ((address = Domain.normalizeHostname(address, true)) != null) {
            String domain = Domain.extractDomainSafe(address, true);
            if (address.endsWith(domain)) {
                boolean removed = false;
                String subdominio = address;
                while (!subdominio.equals(domain)) {
                    String value = getExact(subdominio);
                    if (value == null) {
                        int index = subdominio.indexOf('.', 1);
                        subdominio = subdominio.substring(index);
                    } else if (email.equals(value) && dropExact(address)) {
                        removed = true;
                    }
                }
                String value = getExact(domain);
                if (email.equals(value) && dropExact(domain)) {
                    removed = true;
                }
                return removed;
            } else {
                String value = getExact(address);
                if (email.equals(value) && dropExact(address)) {
                    return true;
                } else {
                    return false;
                }
            }
        } else {
            return false;
        }
    }
    
    public static boolean dropSafe(String address) {
        try {
            return drop(address);
        } catch (ProcessException ex) {
            Server.logError(ex);
            return false;
        }
    }
    
    public static boolean drop(String address) throws ProcessException {
        if ((address = normalizeAddress(address)) == null) {
            throw new ProcessException("INVALID ADDRESS");
        } else {
            return dropExact(address);
        }
    }

    public static void load() {
        long time = System.currentTimeMillis();
        File file = new File("./data/abuse.map");
        if (file.exists() && Core.isMatrixDefence()) {
            try {
                Map<String,String> map;
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    map = SerializationUtils.deserialize(fileInputStream);
                }
                for (String domain : map.keySet()) {
                    String email = map.get(domain);
                    email = email.replaceAll("[\\s\\t]+", "");
                    email = Domain.normalizeEmail(email);
                    if (email != null) {
                        putExact(domain, email);
                    }
                }
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    public static boolean offer(
            long time, String ip, String fqdn,
            String sender, Qualifier qualifier,
            Message report
    ) {
        String email = Abuse.getEmail(
                ip, fqdn, sender, qualifier
        );
        return offer(email, time, report);
    }
    
    public static boolean offer(String email, long time, Message report) {
        if (email == null) {
            return false;
        } else if (isSubscribed(email)) {
            THREAD.put(email, time, report);
            return true;
        } else {
            return false;
        }
    }
    
    public static boolean offer(long time, User.Query query) {
        if (query == null) {
            return false;
        } else if (System.currentTimeMillis() - time > Server.DAY_TIME) {
            return false;
        } else if (query.isAbuseAdvised()) {
            return false;
        } else {
            String email = query.getAbuseSender();
            if (email == null) {
                return false;
            } else if (isUnsubscribed(email)) {
                return false;
            } else {
                THREAD.put(email, time, query);
                return true;
            }
        }
    }
    
    public static boolean reportAbuseSafe(
            long time,
            String client,
            User user,
            String mailFrom,
            String recipient,
            String ip,
            String hostname,
            Qualifier qualifier,
            String unblockURL
    ) {
        try {
            return reportAbuse(
                    time, client, user, mailFrom, recipient, ip, hostname,
                    qualifier == null ? "NONE" : qualifier.name(), unblockURL
            );
        } catch (Exception ex) {
            Server.logError(ex);
            return false;
        }
    }
    
    public static boolean reportAbuse(
            long time,
            String client,
            User user,
            String mailFrom,
            String recipient,
            String ip,
            String hostname,
            String qualifier,
            String unblockURL
    ) throws Exception {
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        }
        return reportAbuse(
                time,
                client,
                userEmail,
                mailFrom,
                recipient,
                ip,
                hostname,
                qualifier,
                unblockURL
        );
    }
    
    public static boolean reportAbuse(
            long time,
            InetAddress clientIP,
            Client client,
            User user,
            String mailFrom,
            String recipient,
            String ip,
            String hostname,
            String qualifier,
            String unblockURL
    ) throws Exception {
        String userEmail = null;
        String clientName = null;
        if (user != null) {
            userEmail = user.getEmail();
        } else if (client != null) {
            userEmail = client.getEmail();
            clientName = client.getDomain();
        }
        String clientFQDN = FQDN.getFQDN(clientIP, false);
        if (clientFQDN != null) {
            clientName = clientFQDN;
        }
        return reportAbuse(
                time,
                clientName,
                userEmail,
                mailFrom,
                recipient,
                ip,
                hostname,
                qualifier,
                unblockURL
        );
    }
    
    public static boolean reportAbuse(
            long time,
            String client,
            String userEmail,
            String mailFrom,
            String recipient,
            String ip,
            String hostname,
            String qualifier,
            String unblockURL
    ) throws Exception {
        String abuseEmail = Abuse.getEmail(
                ip, hostname, mailFrom, qualifier
        );
        if (abuseEmail == null) {
            return false;
        } else if (!Core.hasAdminEmail()) {
            return false;
        } else if (!Core.hasOutputSMTP()) {
            return false;
        } else if (mailFrom == null && Provider.containsIPorFQDN(ip)) {
            return false;
        } else if (Trap.containsAnythingExact(abuseEmail)) {
            Abuse.dropAllEmail(abuseEmail);
            return false;
        } else if (isSubscribed(abuseEmail)) {
            return false;
        } else {
            String arrivalDate = Core.getEmailDate(new Date(time));
            InternetAddress[] recipients = InternetAddress.parse(abuseEmail);
            MimeMessage message = Abuse.newAbuseReportMessage(
                    time,
                    recipients,
                    userEmail,
                    client,
                    null,
                    mailFrom,
                    recipient,
                    arrivalDate,
                    ip,
                    hostname,
                    qualifier,
                    null,
                    null,
                    null,
                    false,
                    unblockURL,
                    null
            );
            offer(abuseEmail, time, message);
            return true;
        }
    }
    
    public static boolean reportAuthFraud(
            long time, String client, String ip
    ) {
        String explanation = "This IP " + ip + " has attempted to perform "
                + "an unauthorized user authentication "
                + "in SMTP server " + client + ".";
        return reportAbuse(time, client, ip, explanation);
    }
    
    public static boolean reportAbuse(
            long time, String client,
            String ip, String explanation
    ) {
        String abuseEmail = Abuse.getEmail(ip);
        if (abuseEmail == null) {
            return false;
        } else if (!Core.hasAdminEmail()) {
            return false;
        } else if (!Core.hasOutputSMTP()) {
            return false;
        } else if (Trap.containsAnythingExact(abuseEmail)) {
            Abuse.dropAllEmail(abuseEmail);
            return false;
        } else if (isSubscribed(abuseEmail)) {
            return false;
        } else {
            try {
                InternetAddress[] recipients = InternetAddress.parse(abuseEmail);
                MimeMessage message = Abuse.newAbuseReportMessage(
                        time,
                        recipients,
                        client,
                        ip,
                        explanation
                );
                offer(abuseEmail, time, message);
                return true;
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        }
    }
    
    public static MimeMessage newAbuseReportMessage(
            long time,
            InternetAddress[] recipients,
            String userEmail,
            String client,
            String malware,
            String mailFrom,
            String recipient,
            String arrivalDate,
            String ip,
            String fqdn,
            String qualifier,
            String messageID,
            TreeSet<String> linkSet,
            Filter filter,
            boolean removalRequest,
            String unblockURL,
            MimeMessage returned
    ) throws Exception {
        if (client == null) {
            client = Core.getHostname();
        }
        if (qualifier == null) {
            qualifier = "none";
        } else {
            qualifier = qualifier.toLowerCase();
        }
        String phishing = null;
        if (linkSet != null) {
            for (String token : linkSet) {
                if (Core.isSignatureURL(token) && Block.containsExact(token)) {
                    if ((phishing = Core.getSignatureRootURL(token)) != null) {
                        break;
                    }
                }
            }
        }
        // Making ARF content.
        InternetHeaders arfHeaders = new InternetHeaders();
        if (malware != null) {
            arfHeaders.addHeader("Feedback-Type", "virus");
        } else if (phishing != null) {
            arfHeaders.addHeader("Feedback-Type", "fraud");
        } else if (filter == Filter.USER_PHISHING) {
            arfHeaders.addHeader("Feedback-Type", "fraud");
        } else {
            arfHeaders.addHeader("Feedback-Type", "abuse");
        }
        arfHeaders.addHeader("User-Agent", "SPFBL/" + Core.getSubVersion());
        arfHeaders.addHeader("Version", "1");
        if (mailFrom == null) {
            arfHeaders.addHeader("Original-Mail-From", "MAILER-DAEMON <>");
        } else {
            arfHeaders.addHeader("Original-Mail-From", '<' + mailFrom + '>');
        }
        if (recipient != null) {
            arfHeaders.addHeader("Original-Rcpt-To", '<' + recipient + '>');
        }
        if (arrivalDate != null) {
            arfHeaders.addHeader("Arrival-Date", arrivalDate);
        }
        arfHeaders.addHeader("Reporting-MTA", "dns; " + client);
        arfHeaders.addHeader("Source-IP", ip);
        if (client != null && mailFrom != null) {
            arfHeaders.addHeader("Authentication-Results", client + "; "
                    + "smtp.mail=" + mailFrom + "; "
                    + "spf=" + qualifier
            );
        }
        if (linkSet != null) {
            for (String token : linkSet) {
                if (Core.isSignatureURL(token)) {
                    if (Block.containsExact(token)) {
                        String url = Core.getSignatureRootURL(token);
                        if (url != null) {
                            arfHeaders.addHeader("Reported-Uri", url);
                            continue;
                        }
                    }
                    token = Core.getSignatureHostURL(token);
                }
                if (Block.findHREF(null, userEmail, token, false) != null) {
                    if (isValidEmail(token)) {
                        arfHeaders.addHeader("Reported-Uri", "mailto:" + token);
                    } else {
                        arfHeaders.addHeader("Reported-Domain", token);
                    }
                }
            }
        }
        if (recipient != null && removalRequest) {
            arfHeaders.addHeader("Removal-Recipient", recipient);
        }
        DispositionNotification report = new DispositionNotification();
        report.setNotifications(arfHeaders);
        // Corpo da mensagem.
        StringBuilder builder = new StringBuilder();
        if ((fqdn = Domain.normalizeHostname(fqdn, false)) == null) {
            builder.append("This is an abuse report for an email message sent by IP ");
            builder.append(ip);
        } else {
            builder.append("This is an abuse report for an email message sent by mail server ");
            builder.append(fqdn);
            builder.append(" [");
            builder.append(ip);
            builder.append("]");
        }
        if (arrivalDate != null) {
            builder.append(" on ");
            builder.append(arrivalDate);
        }
        builder.append("\r\n\r\n");
        if (!Core.isMatrixDefence()) {
            builder.append("You are receiving this abuse report because your IP is registered at https://spfbl.net/en/dnsal\r\n\r\n");
        }
        boolean harmful = false;
        if (malware != null) {
            harmful = true;
            builder.append("A malware was found and defined as ");
            builder.append(malware);
            builder.append("\r\n\r\n");
        } else if (phishing != null) {
            harmful = true;
            builder.append("A phishing was located inside website ");
            builder.append(phishing);
            builder.append("\r\n\r\n");
        } else if (filter == Filter.USER_PHISHING) {
            harmful = true;
            builder.append("This message was classified as phishing by the user.\r\n\r\n");
        } else if (fqdn == null && (qualifier.equals("none") || qualifier.equals("neutral"))) {
            harmful = true;
            builder.append("This source machine appears to not have a regular MTA, because our system could't identify it.\r\n\r\n");
        } else if ((fqdn == null && qualifier.equals("softfail")) || qualifier.equals("fail")) {
            harmful = true;
            builder.append("This abuse appears to be a spoofing attack or its sender has a wrong SPF configuration for sure.\r\n\r\n");
        } else if (!qualifier.equals("pass") && Ignore.containsExact(Domain.extractDomainSafe(mailFrom, true))) {
            harmful = true;
            builder.append("This abuse appears to be a spoofing attack or its sender has a wrong SPF configuration for sure.\r\n\r\n");
        } else if (!qualifier.equals("pass") && Objects.equals(mailFrom, recipient)) {
            harmful = true;
            builder.append("This abuse appears to be a spoofing attack or its sender has a wrong SPF configuration for sure.\r\n\r\n");
        } else if (unblockURL != null) {
            builder.append("If you believe that this report is a mistake, request to recipient the release of this sender at ");
            builder.append(unblockURL);
            builder.append("\r\n\r\n");
        } else if (removalRequest) {
            builder.append("The recipient doesn't want to receive messages from the same sender, ");
            builder.append("so this sender must be forced to stop it.\r\n\r\n");
        }
        if (harmful && Core.hasAdminEmail()) {
            builder.append("If you have any question about this abuse, contact the anti-spam administrator [");
            builder.append(Core.getAdminEmail());
            builder.append("].\r\n\r\n");
        } else if (!harmful && userEmail != null) {
            builder.append("If you have any question about this abuse, contact the mail box administrator [");
            builder.append(userEmail);
            builder.append("].\r\n\r\n");
        }
        builder.append("For more information about this abuse format below, ");
        builder.append("see https://tools.ietf.org/html/rfc5965\r\n\r\n");
        Enumeration enumeration = arfHeaders.getAllHeaderLines();
        while (enumeration.hasMoreElements()) {
            String line = (String) enumeration.nextElement();
            line = line.replace('<', '[');
            line = line.replace('>', ']');
            builder.append("\t");
            builder.append(line);
            builder.append("\r\n");
        }
        builder.append("\r\n");
        if (returned == null) {
            builder.append("This email message was rejected at RCPT TO command, ");
            builder.append("so we don't have its headers.\r\n\r\n");
        } else {
            builder.append("Follows some headers of this email message:\r\n\r\n");
            enumeration = returned.getAllHeaderLines();
            while (enumeration.hasMoreElements()) {
                String line = (String) enumeration.nextElement();
                line = line.replace('<', '[');
                line = line.replace('>', ']');
                builder.append("\t");
                builder.append(line);
                builder.append("\r\n");
            }
        }
        // Join both parts.
        MultipartReport content = new MultipartReport();
        content.setText(builder.toString());
        content.setReport(report);
        content.getBodyPart(1).setHeader("Content-Type", "message/feedback-report");
        if (returned != null && returned.getSize() < 4194304) {
            content.setReturnedMessage(returned);
            content.getBodyPart(2).setHeader("Content-Disposition", "inline");
        }
        // Set multiplart content.
        MimeMessage message = Core.newMessage(true);
        message.addRecipients(Message.RecipientType.TO, recipients);
        message.setSubject("Abuse report #" + Long.toString(time, 32) + " from " + ip);
        message.setContent(content);
        String contentType = message.getDataHandler().getContentType();
        contentType = contentType.replace(
                "report-type=disposition-notification",
                "report-type=feedback-report"
        );
        message.setHeader("Content-Type", contentType);
        message.saveChanges();
        return message;
    }
    
    public static MimeMessage newAbuseReportMessage(
            long time,
            InternetAddress[] recipients,
            String client,
            String ip,
            String explanation
    ) throws Exception {
        String arrivalDate = Core.getEmailDate(new Date(time));
        // Making ARF content.
        InternetHeaders arfHeaders = new InternetHeaders();
        arfHeaders.addHeader("Feedback-Type", "fraud");
        arfHeaders.addHeader("User-Agent", "SPFBL/" + Core.getSubVersion());
        arfHeaders.addHeader("Version", "1");
        arfHeaders.addHeader("Original-Mail-From", "<>");
        arfHeaders.addHeader("Arrival-Date", arrivalDate);
        arfHeaders.addHeader("Reporting-MTA", "dns; " + client);
        arfHeaders.addHeader("Source-IP", ip);
        DispositionNotification report = new DispositionNotification();
        report.setNotifications(arfHeaders);
        // Corpo da mensagem.
        StringBuilder builder = new StringBuilder();
        builder.append("This is an abuse report for a fraud made by IP ");
        builder.append(ip);
        builder.append(" on ");
        builder.append(arrivalDate);
        builder.append("\r\n\r\n");
        if (!Core.isMatrixDefence()) {
            builder.append("You are receiving this abuse report because your IP is registered at https://spfbl.net/en/dnsal\r\n\r\n");
        }
        builder.append(explanation);
        builder.append("\r\n\r\n");
        if (Core.hasAdminEmail()) {
            builder.append("If you have any question about this abuse, contact the anti-spam administrator <");
            builder.append(Core.getAdminEmail());
            builder.append(">.\r\n\r\n");
        }
        builder.append("For more information about this report format below, read the RFC 5965:\r\n");
        builder.append("https://tools.ietf.org/html/rfc5965\r\n\r\n");
        builder.append("The AbuseIO can help you sort and process our reports:\r\n");
        builder.append("https://abuse.io/abuseio/features/\r\n\r\n");
        Enumeration enumeration = arfHeaders.getAllHeaderLines();
        while (enumeration.hasMoreElements()) {
            String line = (String) enumeration.nextElement();
            line = line.replace('<', '[');
            line = line.replace('>', ']');
            builder.append("\t");
            builder.append(line);
            builder.append("\r\n");
        }
        builder.append("\r\n");
        // Join both parts.
        MultipartReport content = new MultipartReport();
        content.setText(builder.toString());
        content.setReport(report);
        content.getBodyPart(1).setHeader("Content-Type", "message/feedback-report");
        // Set multiplart content.
        MimeMessage message = Core.newMessage(true);
        message.addRecipients(Message.RecipientType.TO, recipients);
        message.setSubject("Abuse report #" + Long.toString(time, 32) + " from " + ip);
        message.setContent(content);
        String contentType = message.getDataHandler().getContentType();
        contentType = contentType.replace(
                "report-type=disposition-notification",
                "report-type=feedback-report"
        );
        message.setHeader("Content-Type", contentType);
        message.saveChanges();
        return message;
    }
    
    private static final File FILE = new File("./data/abuse.txt");
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
    
    public static void loadTXT() {
        long time = System.currentTimeMillis();
        if (FILE.exists()) {
            String line;
            try (BufferedReader reader = new BufferedReader(new FileReader(FILE))) {
                while ((line = reader.readLine()) != null) {
                    try {
                        StringTokenizer tokenizer = new StringTokenizer(line, " ");
                        String token = tokenizer.nextToken();
                        if (token.equals("PUT")) {
                            if (Core.isMatrixDefence()) {
                                String key = tokenizer.nextToken();
                                String value = tokenizer.nextToken();
                                putMap(key, value);
                            }
                        } else if (token.equals("DROP")) {
                            String key = tokenizer.nextToken();
                            removeMap(key);
                        } else if (token.equals("REP")) {
                            String abuse = tokenizer.nextToken();
                            abuse = abuse.replaceAll("[\\s\\t]+", "");
                            abuse = Domain.normalizeEmail(abuse);
                            if (abuse != null) {
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
                                loadReputation(abuse, xiSum, xi2Sum, last, flag, min, max);
                            }
                        } else if (token.equals("QUEUE")) {
                            String domain = tokenizer.nextToken();
                            Byte value = tokenizer.hasMoreTokens() ? Byte.parseByte(tokenizer.nextToken()) : null;
                            addOperation(domain, value);
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
    
    private static final int EXPIRATION = 4;

    public static boolean store() {
        try {
            long time = System.currentTimeMillis();
            SEMAPHORE.acquire();
            try {
                WRITER.close();
                Path source = FILE.toPath();
                Path temp = source.resolveSibling('.' + FILE.getName());
                try (FileWriter writer = new FileWriter(temp.toFile())) {
                    if (Core.isMatrixDefence()) {
                        for (String key : getKeySet()) {
                            String value = getExact(key);
                            if (value != null) {
                                writer.write("PUT ");
                                writer.write(key);
                                writer.write(' ');
                                writer.write(value);
                                 writer.write('\n');
                                writer.flush();
                            }
                        }
                    }
                    for (String abuse : getAbuseKeySet()) {
                        Reputation reputation = getReputation(abuse);
                        if (reputation == null) {
                            dropReputation(abuse);
                        } else if (reputation.isExpired(EXPIRATION)) {
                            dropReputation(abuse);
                        } else {
                            float[] xiResult = reputation.getXiSum();
                            Object flag = reputation.getFlagObject();
                            byte[] extremes = reputation.getExtremes();
                            int last = reputation.getLast();
                            writer.write("REP ");
                            writer.write(abuse);
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
                        }
                    }
                    THREAD.store(writer);
                }
                Files.move(temp, source, REPLACE_EXISTING);
                Server.logStore(time, FILE);
                new File("./data/abuse.map").delete();
                return true;
            } finally {
                startWriter();
            }
        } catch (Exception ex) {
            Server.logError(ex);
            return false;
        }
    }
    
    public static boolean isBeneficialFQDN(String fqdn) {
        String abuse = Abuse.getEmailFQDN(fqdn);
        Flag flag = Abuse.getFlag(abuse);
        return flag == BENEFICIAL;
    }
    
    public static boolean isSubscribedBeneficial(String ip) {
        String fqdn = FQDN.getFQDN(ip, false);
        String abuse = Abuse.getEmail(ip, fqdn);
        if (isUnsubscribed(abuse)) {
            return false;
        } else {
            Flag flag = Abuse.getFlag(abuse);
            return flag == BENEFICIAL;
        }
    }
    
    public static boolean isBeneficial(String ip) {
        String fqdn = FQDN.getFQDN(ip, false);
        String abuse = Abuse.getEmail(ip, fqdn);
        Flag flag = Abuse.getFlag(abuse);
        return flag == BENEFICIAL;
    }
    
    public static boolean isHarmfulIP(String ip) {
        String fqdn = FQDN.getFQDN(ip, false);
        return isHarmful(ip, fqdn);
    }
    
    public static boolean isUndesirableRange(String ip) {
        if (ip == null) {
            return false;
        } else if (CIDR.isUndesirable(ip)) {
            String fqdn = FQDN.getFQDN(ip, false);
            String abuse = Abuse.getEmail(ip, fqdn);
            if (abuse == null) {
                return false;
            } else if (Ignore.containsExact(abuse)) {
                return false;
            } else {
                Flag flag = Abuse.getFlag(abuse);
                if (flag == HARMFUL) {
                    return true;
                } else if (flag == UNDESIRABLE) {
                    return isUnsubscribed(abuse);
                } else {
                    return false;
                }
            }
        } else {
            return false;
        }
    }
    
    public static boolean isHarmful(String ip, String fqdn) {
        String abuse = Abuse.getEmail(ip, fqdn);
        Flag flag = Abuse.getFlag(abuse);
        return flag == HARMFUL;
    }
    
    public static boolean addHarmful(String ip, String fqdn) {
        String abuse = Abuse.getEmail(ip, fqdn);
        return addHarmful(abuse);
    }
    
    public static boolean addHarmful(String abuse) {
        if (abuse == null) {
            return false;
        } else {
            return addOperation(abuse, (byte) -4);
        }
    }
    
    public static boolean addUndesirable(String ip, String fqdn) {
        String abuse = Abuse.getEmail(ip, fqdn);
        return addUndesirable(abuse);
    }
    
    public static boolean addUndesirable(String abuse) {
        if (abuse == null) {
            return false;
        } else {
            return addOperation(abuse, (byte) -2);
        }
    }
    
    public static boolean addUnacceptable(String ip, String fqdn) {
        String abuse = Abuse.getEmail(ip, fqdn);
        return addUnacceptable(abuse);
    }
    
    public static boolean addUnacceptable(String abuse) {
        if (abuse == null) {
            return false;
        } else {
            return addOperation(abuse, (byte) -1);
        }
    }
    
    public static boolean addAcceptable(String ip, String fqdn) {
        String abuse = Abuse.getEmail(ip, fqdn);
        return addAcceptable(abuse);
    }
    
    public static boolean addAcceptable(String abuse) {
        if (abuse == null) {
            return false;
        } else {
            return addOperation(abuse, (byte) 1);
        }
    }
    
    public static boolean addDesirable(String ip, String fqdn) {
        String abuse = Abuse.getEmail(ip, fqdn);
        return addDesirable(abuse);
    }
    
    public static boolean addDesirable(String abuse) {
        if (abuse == null) {
            return false;
        } else {
            return addOperation(abuse, (byte) 2);
        }
    }
    
    public static boolean addBeneficial(String ip, String fqdn) {
        String abuse = Abuse.getEmail(ip, fqdn);
        return addBeneficial(abuse);
    }
    
    public static boolean addBeneficial(String abuse) {
        if (abuse == null) {
            return false;
        } else {
            return addOperation(abuse, (byte) 4);
        }
    }
    
    private static boolean addOperation(String abuse, Byte value) {
        if (abuse == null) {
            return false;
        } else if (value == null) {
            return false;
        } else {
            THREAD.offer(new SimpleImmutableEntry<>(abuse, value));
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
    
    private static final int POPULATION = 2048;
    
    private static final HashMap<String,Reputation> REPUTATION_MAP = new HashMap<>();
    
    private synchronized static TreeSet<String> getAbuseKeySet() {
        TreeSet<String> keySet = new TreeSet<>();
        keySet.addAll(REPUTATION_MAP.keySet());
        return keySet;
    }
    
    private static boolean containsKey(String abuse) {
        return REPUTATION_MAP.containsKey(abuse);
    }
    
    private synchronized static void put(String abuse, Reputation reputation) {
        REPUTATION_MAP.put(abuse, reputation);
    }
    
    public static boolean clearReputation(String abuse) {
        if (abuse == null) {
            return false;
        } else if (containsKey(abuse)) {
            Reputation reputation = new Reputation();
            put(abuse, reputation);
            Flag flag = reputation.refreshFlag(POPULATION, false);
            byte[] extremes = reputation.getExtremes();
            float[] xisArray = reputation.getXiSum();
            int last = reputation.getLast();
            append(
                    "REP " + abuse + " " + xisArray[0] + " " + xisArray[1]
                            + " " + last + " " + flag + " "
                            + extremes[0] + " " + extremes[1]
            );
            return true;
        } else {
            return false;
        }
    }
    
    private static Reputation getReputation(String abuse) {
        if (abuse == null) {
            return null;
        } else {
            return REPUTATION_MAP.get(abuse);
        }
    }
    
    private synchronized static boolean dropReputation(String abuse) {
        if (abuse == null) {
            return false;
        } else {
            return REPUTATION_MAP.remove(abuse) != null;
        }
    }
    
    private synchronized static Reputation newReputation(String abuse) {
        if (abuse == null) {
            return null;
        } else {
            Reputation reputation = REPUTATION_MAP.get(abuse);
            if (reputation == null) {
                reputation = new Reputation();
                REPUTATION_MAP.put(abuse, reputation);
            }
            return reputation;
        }
    }
    
    public static Flag getFlag(String abuse) {
        if (abuse == null) {
            return null;
        } else {
            abuse = Domain.normalizeEmail(abuse);
            Flag defaultFlag = isSubscribed(abuse) ? ACCEPTABLE : UNACCEPTABLE;
            Reputation reputation = getReputation(abuse);
            if (reputation == null) {
                return defaultFlag;
            } else {
                return reputation.getFlag(defaultFlag);
            }
        }
    }
    
    public static Flag getFlag(String ip, String fqdn) {
        String abuse = getEmail(ip, fqdn);
        if (abuse == null) {
            return UNACCEPTABLE;
        } else {
            Flag flag = getFlag(abuse);
            if (flag == BENEFICIAL && isUnsubscribed(abuse)) {
                flag = DESIRABLE;
            } else if (flag == HARMFUL && Ignore.containsExact(abuse)) {
                flag = UNDESIRABLE;
            }
            return flag;
        }
    }
    
    private synchronized static void loadReputation(
            String abuse,
            float xiSum,
            float xi2Sum,
            int last,
            String flag,
            byte minimum,
            byte maximum
    ) {
        if (abuse != null) {
            Reputation reputation = REPUTATION_MAP.get(abuse);
            if (reputation == null) {
                reputation = new Reputation();
                REPUTATION_MAP.put(abuse, reputation);
            }
            reputation.set(xiSum, xi2Sum, last, flag, minimum, maximum);
        }
    }
    
    private static class ProcessThread extends Thread {
        
        private final LinkedList<SimpleImmutableEntry> QUEUE = new LinkedList<>();
        private final TreeMap<String,TreeMap<Long,Object>> MAP = new TreeMap<>();
        private boolean run = true;
        
        private synchronized void put(String email, long time, User.Query query) {
            if (email != null) {
                TreeMap<Long,Object> map = MAP.get(email);
                if (map == null) {
                    map = new TreeMap<>();
                    MAP.put(email, map);
                }
                map.put(time, query);
                notify();
            }
        }
        
        private synchronized void put(String email, Long time, Message report) {
            if (email != null && time != null) {
                TreeMap<Long,Object> map = MAP.get(email);
                if (map == null) {
                    map = new TreeMap<>();
                    MAP.put(email, map);
                }
                map.put(time, report);
                notify();
            }
        }
        
        private synchronized String next(String email) {
            if (MAP.isEmpty()) {
                return null;
            } else if (email == null) {
                return MAP.firstKey();
            } else {
                return MAP.higherKey(email);
            }
        }
        
        private synchronized Entry<Long,Object> poll(String email) {
            if (email == null) {
                return null;
            } else {
                TreeMap<Long,Object> map = MAP.get(email);
                if (map == null) {
                    return null;
                } else {
                    Entry<Long,Object> entry = map.pollFirstEntry();
                    if (map.isEmpty()) {
                        MAP.remove(email);
                    }
                    return entry;
                }
            }
        }
        
        private synchronized void drop(String email) {
            if (email != null) {
                MAP.remove(email);
            }
        }
        
        private synchronized int size(String email) {
            if (email == null) {
                return 0;
            } else {
                TreeMap<Long,Object> map = MAP.get(email);
                if (map == null) {
                    return 0;
                } else {
                    return map.size();
                }
            }
        }
        
        private ProcessThread() {
            super("ABUSETHRD");
            setPriority(Thread.MIN_PRIORITY);
        }
        
        private synchronized void offer(SimpleImmutableEntry<String,Byte> entry) {
            if (entry.getValue() == null) {
                Server.logError(new Exception("null value"));
            }
            QUEUE.offer(entry);
            notify();
        }
        
        private synchronized SimpleImmutableEntry poll() {
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
                while (Core.isRunning() && continueRun()) {
                    processQueue();
                    processMap();
                    waitNext();
                }
            } finally {
                Server.logTrace("thread closed.");
            }
        }
        
        private void processQueue() {
            SimpleImmutableEntry<String,Byte> entry;
            while (Core.isRunning() && (entry = poll()) != null) {
                String abuse = entry.getKey();
                Byte value = entry.getValue();
                abuse = Domain.normalizeEmail(abuse);
                if (abuse != null && value != null) {
                    Reputation reputation = newReputation(abuse);
                    Flag oldFlag = reputation.getFlag();
                    reputation.add(value, POPULATION);
                    Flag newFlag = reputation.refreshFlag(POPULATION, false);
                    byte[] extremes = reputation.getExtremes();
                    if (newFlag != oldFlag) {
                        float[] xisArray = reputation.getXiSum();
                        int last = reputation.getLast();
                        append(
                                "REP " + abuse + " " + xisArray[0] + " " + xisArray[1]
                                        + " " + last + " " + newFlag + " "
                                        + extremes[0] + " " + extremes[1]
                        );
                    }
                    if (value == -4 && extremes[0] < -3 && extremes[1] < -1) {
                        if (Core.isMatrixDefence()) {
                            if (!Ignore.containsExact(abuse) && NoReply.addSafe(abuse)) {
                                Server.logInfo(
                                        "abuse address '" + abuse + "' was "
                                                + "unsubscribed by 'HARMFUL'."
                                );
                            }
                        }
                    }
                }
            }
        }
        
        private void processMap() {
            String email = null;
            Entry<Long,Object> entry;
            while (Core.isRunning() && (email = next(email)) != null) {
                if (isUnsubscribed(email)) {
                    drop(email);
                } else if (Trap.containsAnythingExact(email)) {
                    drop(email);
                } else {
                    while ((entry = poll(email)) != null) {
                        long time = entry.getKey();
                        User.Query query = null;
                        if (System.currentTimeMillis() - time < Server.DAY_TIME) {
                            try {
                                int size = size(email) + 1;
                                Server.logTrace(size + " entries in '" + email + "' queue.");
                                Object value = entry.getValue();
                                if (value instanceof Message) {
                                    Message report = (Message) value;
                                    Server.logInfo("sending abuse report to " + email + ".");
                                    if (ServerSMTP.sendMessage(Locale.US, report, email, null)) {
                                        Defer.end(">" + email);
                                        Server.logInfo("abuse report sent to " + email + ".");
                                    } else {
                                        Server.logInfo("abuse report not sent to " + email + ".");
                                    }
                                } else if (value instanceof User.Query) {
                                    query = (User.Query) value;
                                    if (query.reportAbuse(time, email)) {
                                        Defer.end(">" + email);
                                        Server.logInfo("abuse report sent to " + email + ".");
                                    } else {
                                        Server.logInfo("abuse report not sent to " + email + ".");
                                    }
                                } else {
                                    Server.logInfo("abuse class not reconized: " + value.getClass());
                                }
                            } catch (MailConnectException ex) {
                                if (!Defer.defer(">" + email, Core.getDeferTimeHOLD())) {
                                    NoReply.addSafe(email);
                                }
                            } catch (SocketTimeoutException ex) {
                                if (!Defer.defer(">" + email, Core.getDeferTimeHOLD())) {
                                    NoReply.addSafe(email);
                                }
                            } catch (SocketConnectException ex) {
                                NoReply.addSafe(email);
                            } catch (IOException ex) {
                                if (query != null) {
                                    query.setAbuseAdvised(null);
                                }
                            } catch (SMTPAddressFailedException ex) {
                                String message = ex.getMessage().toLowerCase().trim();
                                if (ex.getReturnCode() == 511 || message.contains(" 5.1.1 ")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 551) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("mailbox not found")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("mailbox does not exist")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("account is disable")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("not active")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("unavailable")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("existe")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("no such user")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("not exist")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("not found")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("no such recipient")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("user unknown")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("no longer")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("this user")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("invalid mailbox")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("nenhuma pessoa")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("address rejected")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("recipient unknown")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("no such person")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("unrouteable address")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("unroutable address")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("currently available")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("invalid recipient")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("user") && message.contains("unknown")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("no mailbox")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("usuario inexistente")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("cuenta desactivada")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("unknown user")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 553 && message.contains("unknown user")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("account disabled")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("relay not permitted")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("not permitted to relay")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("invalide recipients")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("user suspended")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("não foi localizado")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("nao existe")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 501 && message.contains("invalid address")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 505 && message.contains("unknown user")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 553 && message.contains("allowed rcpthosts")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 553 && message.contains("no mail-box")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 554 && message.contains("dosn't exist")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 554 && message.contains("doesn't exist")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 557 && message.contains("not available")) {
                                    Trap.addInexistentForever(email);
                                    dropAllEmail(email);
                                } else if (ex.getReturnCode() == 591) {
                                    NoReply.addSafe(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("cannot accept")) {
                                    NoReply.addSafe(email);
                                } else if (ex.getReturnCode() / 100 == 5 && message.equals("[EOF]")) {
                                    NoReply.addSafe(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("blacklisted")) {
                                    NoReply.addSafe(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("black list")) {
                                    NoReply.addSafe(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("blocked")) {
                                    NoReply.addSafe(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("not allowed")) {
                                    NoReply.addSafe(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("invalid address")) {
                                    NoReply.addSafe(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("mailbox is full")) {
                                    NoReply.addSafe(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("mailbox quota")) {
                                    NoReply.addSafe(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("limit exceeded")) {
                                    NoReply.addSafe(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("denied")) {
                                    NoReply.addSafe(email);
                                } else if (ex.getReturnCode() == 550 && message.contains("not accept")) {
                                    NoReply.addSafe(email);
                                } else if (ex.getReturnCode() == 550 && message.contains(" 5.2.1 ")) {
                                    NoReply.addSafe(email);
                                } else if (ex.getReturnCode() == 550 && message.equals("550")) {
                                    NoReply.addSafe(email);
                                } else if (ex.getReturnCode() == 552 && message.contains(" 5.2.2 ")) {
                                    NoReply.addSafe(email);
                                } else if (ex.getReturnCode() == 550 && message.equals("")) {
                                    NoReply.addSafe(email);
                                } else if (ex.getReturnCode() == 530 || message.contains(" 5.7.0 ")  || message.contains(" 5.7.1 ") || message.contains(" 5.4.1 ") || message.contains(" 5.1.0 ")) {
                                    NoReply.addSafe(email);
                                } else if (ex.getReturnCode() == 454 || message.contains(" 4.7.1 ")) {
                                    NoReply.addSafe(email);
                                } else if (ex.getReturnCode() == 450 && message.contains(" 4.1.8 ")) {
                                    // Sender getAddressIP rejected: Domain not found
                                    NoReply.addSafe(email);
                                } else if (ex.getReturnCode() / 100 == 4) {
                                    int deferTime = Ignore.containsExact(email) ?
                                            Core.getDeferTimeHOLD() :
                                            Core.getDeferTimeRED();
                                    if (!Defer.defer(">" + email, deferTime)) {
                                        NoReply.addSafe(email);
                                    }
                                } else if (query != null && ex.getReturnCode() / 100 == 5) {
                                    query.setAbuseAdvised(null);
                                    Server.logError(ex);
                                } else {
                                    Server.logError(ex);
                                }
                            } catch (SendFailedException ex) {
                                if (!Defer.defer(">" + email, Core.getDeferTimeRED())) {
                                    NoReply.addSafe(email);
                                }
                            } catch (NameNotFoundException ex) {
                                Trap.addInexistentForever(email);
                                dropAllEmail(email);
                            } catch (MessagingException | ServiceUnavailableException ex) {
                                if (!Defer.defer(">" + email, Core.getDeferTimeHOLD())) {
                                    NoReply.addSafe(email);
                                }
                            } catch (Exception ex) {
                                Server.logError(ex);
                            }
                            break;
                        } else {
                            Server.logInfo("expired abuse report #" + Long.toString(time, 32) + " to <" + email + ">.");
                        }
                    }
                }
            }
        }
        
        private void store(FileWriter writer) throws IOException {
            if (!Core.isRunning()) {
                SimpleImmutableEntry<String,Byte> entry;
                while ((entry = poll()) != null) {
                    String abuse = entry.getKey();
                    Byte value = entry.getValue();
                    writer.write("QUEUE ");
                    writer.write(abuse);
                    if (value == null) {
                        Server.logError("QUEUE " + abuse + " null");
                    } else {
                        writer.write(' ');
                        writer.write(Byte.toString(value));
                    }
                    writer.write('\n');
                    writer.flush();
                }
            }
        }
    }
}
