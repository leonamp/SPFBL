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

import com.sun.mail.dsn.DispositionNotification;
import com.sun.mail.dsn.MultipartReport;
import com.sun.mail.smtp.SMTPAddressFailedException;
import com.sun.mail.smtp.SMTPSendFailedException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.SendFailedException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.InternetHeaders;
import javax.mail.internet.MimeMessage;
import javax.naming.CommunicationException;
import javax.naming.NameNotFoundException;
import javax.naming.ServiceUnavailableException;
import net.spfbl.core.Client;
import net.spfbl.core.Core;
import net.spfbl.core.ProcessException;
import net.spfbl.core.Reverse;
import net.spfbl.core.Server;
import net.spfbl.core.User;
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
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean CHANGED = false;

    private synchronized static boolean dropExact(String domain) {
        if (domain == null) {
            return false;
        } else if (MAP.remove(domain) == null) {
            return false;
        } else {
            return CHANGED = true;
        }
    }
    
    private synchronized static boolean containsExact(String address) {
        return MAP.containsKey(address);
    }
    
    private synchronized static String getExact(String address) {
        return MAP.get(address);
    }
    
    private synchronized static boolean putExact(String address, String email) {
        if (address == null || email == null) {
            return false;
        } else {
            String addressOld = MAP.put(address, email);
            if (addressOld == null) {
                return CHANGED = true;
            } else if (addressOld.equals(email)) {
                return false;
            } else {
                return CHANGED = true;
            }
        }
    }

    public synchronized static TreeSet<String> getKeySet() {
        TreeSet<String> domainSet = new TreeSet<>();
        domainSet.addAll(MAP.keySet());
        return domainSet;
    }
    
    public synchronized static HashMap<String,String> getMap() {
        HashMap<String,String> map = new HashMap<>();
        map.putAll(MAP);
        return map;
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
        if (SubnetIPv4.isValidIPv4(token)) {
            return SubnetIPv4.normalizeCIDRv4(token + "/32");
        } else if (SubnetIPv6.isValidIPv6(token)) {
            return SubnetIPv6.normalizeCIDRv6(token + "/128");
        } else if (Subnet.isValidCIDR(token)) {
            return Subnet.normalizeCIDR(token);
        } else if (Domain.isHostname(token)) {
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
        if ((address = normalizeAddress(address)) == null) {
            throw new ProcessException("INVALID ADDRESS");
        } else if (!Domain.isValidEmail(email = email.toLowerCase())) {
            throw new ProcessException("INVALID EMAIL");
        } else {
            Server.logTrace("ABUSE ADDED " + address + " " + email);
            return putExact(address, email);
        }
    }
    
    private static String DNSAL = "abuse.spfbl.net";
    
    public static void dropExternalDNSAL() {
        DNSAL = null;
    }
    
    private static String getExternalDNSAL() {
        return DNSAL;
    }
    
    private static boolean isExternalDNSAL(String dnsal) {
        if (dnsal == null) {
            return false;
        } else if (DNSAL == null) {
            return false;
        } else {
            return dnsal.equals(DNSAL);
        }
    }
    
    public static boolean hasExternalDNSAL() {
        return DNSAL != null;
    }
    
    public static String getEmail(String address) {
        String zone;
        if (address == null) {
            return null;
        } else if ((zone = getExternalDNSAL()) != null) {
            String host = null;
            if (Subnet.isValidIP(address)) {
                host = Reverse.getHostReverse(address, zone);
            } else if ((address = Domain.normalizeHostname(address, false)) != null) {
                host = address + "." + zone;
            }
            if (host == null) {
                return null;
            } else {
                try {
                    ArrayList<String> txtSet = Reverse.getTXTSet(host);
                    if (txtSet == null || txtSet.isEmpty()) {
                        return null;
                    } else {
                        return txtSet.get(0);
                    }
                } catch (CommunicationException ex) {
                    return null;
                } catch (NameNotFoundException ex) {
                    return null;
                } catch (Exception ex) {
                    Server.logError(ex);
                    return null;
                }
            }
        } else if (SubnetIPv4.isValidIPv4(address)) {
            for (int mask = 32; mask > 0; mask--) {
                String cidr = SubnetIPv4.normalizeCIDRv4(address + "/" + mask);
                String email = getExact(cidr);
                if (email != null) {
                    return email;
                }
            }
            return null;
        } else if (SubnetIPv6.isValidIPv6(address)) {
            for (int mask = 128; mask > 0; mask--) {
                String cidr = SubnetIPv6.normalizeCIDRv6(address + "/" + mask);
                String email = getExact(cidr);
                if (email != null) {
                    return email;
                }
            }
            return null;
        } else if (Subnet.isValidCIDR(address)) {
            String ip = Subnet.getFirstIP(address);
            for (int mask = Subnet.getMask(address); mask > 0; mask--) {
                String cidr = Subnet.normalizeCIDR(ip + "/" + mask);
                String email = getExact(cidr);
                if (email != null) {
                    return email;
                }
            }
            return null;
        } else if ((address = Domain.normalizeHostname(address, true)) != null) {
            try {
                String domain = Domain.extractDomain(address, true);
                if (domain == null) {
                    return getExact(address);
                } else if (address.endsWith(domain)) {
                    String subdominio = address;
                    while (!subdominio.equals(domain)) {
                        String email = getExact(subdominio);
                        if (email == null) {
                            int index = subdominio.indexOf('.', 1);
                            subdominio = subdominio.substring(index);
                        } else {
                            return email;
                        }
                    }
                    return getExact(domain);
                } else {
                    return getExact(address);
                }
            } catch (ProcessException ex) {
                return getExact(address);
            }
        } else {
            return null;
        }
    }
    
    public static boolean containsEmail(String address) {
        return getEmail(address) != null;
    }
    
    public static boolean dropEmail(String address, String email) {
        if (address == null) {
            return false;
        } else if (email == null) {
            return false;
        } else if (SubnetIPv4.isValidIPv4(address)) {
            email = email.toLowerCase();
            boolean removed = false;
            for (int mask = 32; mask > 0; mask--) {
                String key = SubnetIPv4.normalizeCIDRv4(address + "/" + mask);
                String value = getExact(key);
                if (email.equals(value) && dropExact(key)) {
                    removed = true;
                }
            }
            return removed;
        } else if (SubnetIPv6.isValidIPv6(address)) {
            email = email.toLowerCase();
            boolean removed = false;
            for (int mask = 128; mask > 0; mask--) {
                String key = SubnetIPv6.normalizeCIDRv6(address + "/" + mask);
                String value = getExact(key);
                if (email.equals(value) && dropExact(key)) {
                    removed = true;
                }
            }
            return removed;
        } else {
            return false;
        }
    }
    
    public static boolean dropCIDR(String address) {
        if (address == null) {
            return false;
        } else if (SubnetIPv4.isValidIPv4(address)) {
            boolean removed = false;
            for (int mask = 32; mask > 0; mask--) {
                String key = SubnetIPv4.normalizeCIDRv4(address + "/" + mask);
                if (dropExact(key)) {
                    removed = true;
                }
            }
            return removed;
        } else if (SubnetIPv6.isValidIPv6(address)) {
            boolean removed = false;
            for (int mask = 128; mask > 0; mask--) {
                String key = SubnetIPv6.normalizeCIDRv6(address + "/" + mask);
                if (dropExact(key)) {
                    removed = true;
                }
            }
            return removed;
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

    public static void store() {
        if (CHANGED) {
            try {
                File file = new File("./data/abuse.map");
                if (hasExternalDNSAL()) {
                    file.delete();
                } else {
                    long time = System.currentTimeMillis();
                    HashMap<String,String> map = getMap();
                    try (FileOutputStream outputStream = new FileOutputStream(file)) {
                        SerializationUtils.serialize(map, outputStream);
                        CHANGED = false;
                    }
                    Server.logStore(time, file);
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }

    public static void load() {
        long time = System.currentTimeMillis();
        File file = new File("./data/abuse.map");
        if (file.exists()) {
            try {
                Map<String,String> map;
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    map = SerializationUtils.deserialize(fileInputStream);
                }
                for (String domain : map.keySet()) {
                    String email = map.get(domain);
                    putExact(domain, email);
                }
                CHANGED = false;
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static SendThread SEND_THREAD = null;
    
    private static synchronized SendThread getSendThread() {
        if (Core.hasAdminEmail() && Core.hasOutputSMTP()) {
            if (SEND_THREAD == null) {
                SEND_THREAD = new SendThread();
                SEND_THREAD.start();
            }
            return SEND_THREAD;
        } else {
            return null;
        }
    }
    
    public static void offerReport(MimeMessage report) {
        SendThread sendThread = getSendThread();
        if (sendThread != null) {
            sendThread.offer(report);
        }
    }
    
    public static synchronized void interrupt() {
        if (SEND_THREAD != null) {
            SEND_THREAD.interrupt();
        }
    }
    
    private static class SendThread extends Thread {
        
        private final LinkedList<MimeMessage> QUEUE = new LinkedList<>();
        private boolean run = true;
        
        private synchronized void offer(MimeMessage report) {
            QUEUE.offer(report);
            notify();
        }
        
        private synchronized MimeMessage poll() {
            return QUEUE.poll();
        }
        
        private synchronized void waitNext() {
            try {
                wait(60000);
            } catch (InterruptedException ex) {
                Server.logError(ex);
            }
        }
        
        private synchronized boolean continueRun() {
            return run;
        }
        
        @Override
        public synchronized void interrupt() {
            run = false;
            notify();
        }
        
        @Override
        public void run() {
            try {
                Thread.currentThread().setName("ABUSETHRD");
                MimeMessage report;
                while (continueRun()) {
                    while (continueRun() && (report = poll()) != null) {
                        String sourceIP = null;
                        String abuseEmail = null;
                        try {
                            Server.logDebug("sending abuse report by e-mail.");
                            String[] sourceArray = report.getHeader("Source-IP");
                            sourceIP = sourceArray == null || sourceArray.length == 0 ? null : sourceArray[0];
                            InternetAddress[] recipientArray = (InternetAddress[]) report.getRecipients(Message.RecipientType.TO);
                            abuseEmail = recipientArray == null || recipientArray.length == 0 ? null : recipientArray[0].getAddress();
                            // Enviar mensagem.
                            if (Core.sendMessage(Locale.US, report, 30000)) {
                                Server.logDebug("abuse report sent by e-mail.");
                            }
                        } catch (CommunicationException ex) {
                            // Do nothing.
                        } catch (NameNotFoundException ex) {
                            dropEmail(sourceIP, abuseEmail);
                        } catch (ServiceUnavailableException ex) {
                            dropEmail(sourceIP, abuseEmail);
                        } catch (SMTPSendFailedException ex) {
                            dropEmail(sourceIP, abuseEmail);
                        } catch (SendFailedException ex) {
                            if (ex.getCause() instanceof SMTPAddressFailedException) {
                                dropEmail(sourceIP, abuseEmail);
                            } else {
                                Server.logError(ex);
                            }
                        } catch (MessagingException ex) {
                            dropEmail(sourceIP, abuseEmail);
                        } catch (Exception ex) {
                            Server.logError(ex);
                        }
                    }
                    waitNext();
                }
            } finally {
                Server.logTrace("thread closed.");
            }
        }
    }
    
    public static boolean reportAbuse(
            long time,
            Client client,
            User user,
            String mailFrom,
            String recipient,
            String ip,
            String unblockURL
    ) throws Exception {
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        } else if (client != null) {
            userEmail = client.getEmail();
        }
        return reportAbuse(
                time,
                userEmail,
                mailFrom,
                recipient,
                ip,
                unblockURL
        );
    }
    
    public static boolean reportAbuse(
            long time,
            String userEmail,
            String mailFrom,
            String recipient,
            String ip,
            String unblockURL
    ) throws Exception {
        String abuseEmail = Abuse.getEmail(ip);
        if (abuseEmail == null) {
            return false;
        } else if (!Core.hasAdminEmail()) {
            return false;
        } else if (!Core.hasOutputSMTP()) {
            return false;
        } else if (NoReply.contains(abuseEmail, true)) {
            Abuse.dropEmail(ip, abuseEmail);
            return false;
        } else {
            String arrivalDate = Core.getEmailDate(new Date(time));
            InternetAddress[] recipients = InternetAddress.parse(abuseEmail);
//            InternetAddress[] bcc = {Core.getAdminInternetAddress()};
            MimeMessage message = Abuse.newAbuseReportMessage(
                    null,
                    null,
                    mailFrom,
                    recipient,
                    arrivalDate,
                    ip,
                    null,
                    false,
                    unblockURL
            );
            message.addRecipients(Message.RecipientType.TO, recipients);
//            message.addRecipients(Message.RecipientType.BCC, bcc);
            if (userEmail != null) {
                message.setReplyTo(InternetAddress.parse(userEmail));
            }
            message.setSubject("Abuse report");
            message.saveChanges();
            offerReport(message);
            return true;
        }
    }
    
    public static MimeMessage newAbuseReportMessage(
            User user,
            String malware,
            String mailFrom,
            String recipient,
            String arrivalDate,
            String ip,
            TreeSet<String> linkSet,
            boolean removalRequest,
            String unblockURL
    ) throws Exception {
        MimeMessage message = Core.newMessage();
        // Making ARF content.
        InternetHeaders arfHeaders = new InternetHeaders();
        arfHeaders.addHeader("Feedback-Type", malware == null ? "abuse" : "virus");
        arfHeaders.addHeader("User-Agent", "SPFBL/" + Core.getSubVersion());
        arfHeaders.addHeader("Version", "1");
        if (mailFrom == null) {
            arfHeaders.addHeader("Original-Mail-From", "MAILER-DAEMON");
        } else {
            arfHeaders.addHeader("Original-Mail-From", mailFrom);
        }
        if (recipient != null) {
            arfHeaders.addHeader("Original-Rcpt-To", recipient);
        }
        arfHeaders.addHeader("Arrival-Date", arrivalDate);
        if (Core.hasHostname()) {
            arfHeaders.addHeader("Reporting-MTA", "dns; " + Core.getHostname());
        }
        arfHeaders.addHeader("Source-IP", ip);
        if (linkSet != null) {
            for (String token : linkSet) {
                if (Core.isSignatureURL(token)) {
                    token = Core.getSignatureHostURL(token);
                }
                if (Block.findHREF(user, token, false) != null) {
                    if (Domain.isValidEmail(token)) {
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
        builder.append("This is an abuse report for an email message received from IP ");
        builder.append(ip);
        builder.append(" on ");
        builder.append(arrivalDate);
        builder.append("\r\n\r\n");
        if (isExternalDNSAL("abuse.spfbl.net")) {
            builder.append("You are receiving this abuse report because your IP is registered at https://spfbl.net/en/dnsal\r\n\r\n");
        }
        if (malware != null) {
            builder.append("A malware was found and defined as ");
            builder.append(malware);
            builder.append("\r\n\r\n");
        } else if (unblockURL != null) {
            builder.append("If you beleave that this report is a mistake, request to recipient the release of this sender at ");
            builder.append(unblockURL);
            builder.append("\r\n\r\n");
        } else if (removalRequest) {
            builder.append("The recipient do not want receive messages from the same sender, ");
            builder.append("so this sender must be forced to stop do it.\r\n\r\n");
        }
        builder.append("For more information about this abuse format below, ");
        builder.append("see https://tools.ietf.org/html/rfc5965\r\n\r\n");
        Enumeration enumeration = arfHeaders.getAllHeaderLines();
        while (enumeration.hasMoreElements()) {
            String line = (String) enumeration.nextElement();
            builder.append(line);
            builder.append("\r\n");
        }
        // Join both parts.
        MultipartReport content = new MultipartReport();
        content.setText(builder.toString());
        content.setReport(report);
        content.getBodyPart(1).setHeader("Content-Type", "message/feedback-report");
        // Set multiplart content.
        message.setContent(content);
        String contentType = message.getDataHandler().getContentType();
        contentType = contentType.replace(
                "report-type=disposition-notification",
                "report-type=feedback-report"
        );
        message.setHeader("Content-Type", contentType);
        message.setHeader("Content-Type", contentType);
        return message;
    }
}
