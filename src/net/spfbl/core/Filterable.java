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
package net.spfbl.core;

import java.net.URL;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Date;
import java.util.Locale;
import java.util.Objects;
import java.util.TreeSet;
import javax.naming.CommunicationException;
import javax.naming.NamingException;
import javax.naming.ServiceUnavailableException;
import static net.spfbl.core.Filterable.Filter.ENVELOPE_HARMFUL;
import static net.spfbl.core.Filterable.Filter.ENVELOPE_UNDESIRABLE;
import static net.spfbl.core.Regex.isHostname;
import static net.spfbl.core.Regex.isValidEmail;
import static net.spfbl.core.Regex.isValidIP;
import net.spfbl.data.Abuse;
import net.spfbl.data.Block;
import net.spfbl.data.CIDR;
import net.spfbl.data.DKIM;
import net.spfbl.data.Dictionary;
import net.spfbl.data.FQDN;
import net.spfbl.data.Generic;
import net.spfbl.data.Ignore;
import net.spfbl.data.NeuralNetwork;
import net.spfbl.data.NoReply;
import net.spfbl.data.Provider;
import net.spfbl.data.Recipient;
import net.spfbl.data.Reputation.Flag;
import static net.spfbl.data.Reputation.Flag.BENEFICIAL;
import static net.spfbl.data.Reputation.Flag.DESIRABLE;
import static net.spfbl.data.Reputation.Flag.HARMFUL;
import static net.spfbl.data.Reputation.Flag.UNDESIRABLE;
import net.spfbl.spf.SPF;
import net.spfbl.spf.SPF.Qualifier;
import static net.spfbl.spf.SPF.Qualifier.PASS;
import net.spfbl.whois.Domain;
import net.spfbl.data.Reputation;
import static net.spfbl.data.Reputation.Flag.ACCEPTABLE;
import static net.spfbl.data.Reputation.Flag.UNACCEPTABLE;
import net.spfbl.data.White;
import static net.spfbl.spf.SPF.Qualifier.FAIL;
import static net.spfbl.spf.SPF.Qualifier.SOFTFAIL;
import net.spfbl.whois.Subnet;

/**
 * Represents all filtrable classes.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public abstract class Filterable {
    
    public abstract String getUserEmail();
    
    public abstract String getClient();
    
    public abstract String getIP();
    
    public abstract String getHELO();
    
    public abstract String getFQDN();
    
    public final boolean hasFQDN() {
        return getFQDN() != null;
    }
    
    public final boolean hasFrom() {
        return getFrom() != null;
    }
    
    public boolean isLocalRouting() {
        String domain1 = Domain.extractDomainSafeNotNull(getClient(), false);
        String domain2 = Domain.extractDomainSafeNotNull(getFQDN(), false);
        if (Objects.equals(domain1, domain2)) {
            return true;
        } else {
            String sender = getSender();
            String from = getFrom();
            String replyto = getReplyTo();
            String[] domain3Array = new String[3];
            domain3Array[0] = isSigned(sender) ? Domain.extractDomainSafeNotNull(sender, false) : null;
            domain3Array[1] = isSigned(from) ? Domain.extractDomainSafeNotNull(from, false) : null;
            domain3Array[2] = isSigned(replyto) ? Domain.extractDomainSafeNotNull(replyto, false) : null;
            for (String recipient : getRecipientList()) {
                domain1 = Domain.extractDomainSafeNotNull(recipient, false);
                for (String domain3 : domain3Array) {
                    if (Objects.equals(domain1, domain3)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
    
    public final String extractRootDomainFQDN() {
        return Domain.extractDomainSafe(getFQDN(), false);
    }
    
    public abstract String getSender();
    
    public static final String getEmailHostname(String email) {
        if (email == null) {
            return null;
        } else {
            int index = email.indexOf('@');
            String host = email.substring(index + 1);
            return Domain.normalizeHostname(host, false);
        }
    }
    
    public final boolean isEnvelopeFreeMail() {
        return Provider.isFreeMail(getSender());
    }
    
    public final static String simplifyEmail(String email) {
        if (email == null) {
            return null;
        } else {
            int index = email.indexOf('@');
            if (index > 0) {
                String domain = email.substring(index);
                if (Provider.containsExact(domain)) {
                    return email;
                } else {
                    return domain;
                }
            } else {
                return null;
            }
        }
    }
    
    public final boolean isBounceMessage() {
        return getSender() == null;
    }
    
    public final boolean isSenderMailerDeamon() {
        String sender = getSender();
        String from = getFrom();
        if (from == null) {
            return sender == null;
        } else if (sender == null) {
            return from.startsWith("mailer-daemon@") || from.startsWith("postmaster@") || from.startsWith("root@");
        } else if (sender.startsWith("mailer-daemon@") && from.startsWith("mailer-daemon@")) {
            return true;
        } else if (sender.startsWith("postmaster@") && from.startsWith("postmaster@")) {
            return true;
        } else if (sender.startsWith("root@") && from.startsWith("root@")) {
            return true;
        } else if (sender.startsWith("admin@") && from.startsWith("admin@")) {
            return true;
        } else if (from.startsWith("admin@")) {
            return true;
        } else if (from.startsWith("postmaster@")) {
            return true;
        } else if (from.startsWith("mailer-daemon@")) {
            return true;
        } else {
            return false;
        }
    }
    
    public abstract Qualifier getQualifier();
    
    public boolean isQualifier(Qualifier... qualifiers) {
        if (qualifiers == null) {
            return false;
        } else if (qualifiers.length == 0) {
            return false;
        } else {
            Qualifier qualifier1 = getQualifier();
            if (qualifier1 == null) {
                return false;
            } else {
                for (Qualifier qualifier2 : qualifiers) {
                    if (qualifier1 == qualifier2) {
                        return true;
                    }
                }
                return false;
            }
        }
    }
    
    public final boolean isPass() {
        return getQualifier() == PASS;
    }
    
    public final boolean isFail() {
        return getQualifier() == FAIL;
    }
    
    public final boolean isSoftfail() {
        return getQualifier() == SOFTFAIL;
    }
    
    public final boolean isInexistent() {
        return Recipient.isInexistent(getUserEmail(), getRecipientFirst());
    }
    
    public final boolean isSpamtrap() {
        return Recipient.isTrap(getUserEmail(), getRecipientFirst());
    }
    
    public final String getAbuseOrigin() {
        return Abuse.getEmail(getIP(), getFQDN());
    }
    
    public final String getAbuseSender() {
        return Abuse.getEmail(getIP(), getFQDN(), getSender(), getQualifier());
    }
    
    public final boolean isAbuseBlocked(
        int usingSince,
        Qualifier qualifier,
        Flag spfFlag,
        String fqdn,
        Filter previous
    ) {
        String user = getUserEmail();
        String abuse = getAbuseOrigin();
        if (user == null) {
            return false;
        } else if (abuse == null) {
            return false;
        } else if (usingSince < 21) {
            return Block.containsExact(user, abuse);
        } else if (qualifier != PASS) {
            return Block.containsExact(user, abuse);
        } else if (spfFlag == HARMFUL) {
            return Block.containsExact(user, abuse);
        } else if (spfFlag == UNDESIRABLE) {
            return Block.containsExact(user, abuse);
        } else if (fqdn == null) {
            return Block.containsExact(user, abuse);
        } else if (previous == ENVELOPE_UNDESIRABLE) {
            return Block.containsExact(user, abuse);
        } else if (previous == ENVELOPE_HARMFUL) {
            return Block.containsExact(user, abuse);
        } else if (isUndesirable()) {
            return Block.containsExact(user, abuse);
        } else {
            return false;
        }
    }
    
    public abstract TreeSet<String> getRecipientSet();
    
    public String getRecipientFirst() {
        TreeSet<String> recipientSet = getRecipientSet();
        if (recipientSet == null) {
            return null;
        } else {
            return recipientSet.first();
        }
    }
    
    public String getRecipientHostname(boolean pontuacao) {
        String recipientLocal = getRecipientFirst();
        if (recipientLocal == null) {
            return null;
        } else {
            int index = recipientLocal.indexOf('@');
            String host = recipientLocal.substring(index + 1);
            return Domain.normalizeHostname(host, pontuacao);
        }
    }
    
    public ArrayList<String> getRecipientList() {
        ArrayList<String> recipientList = new ArrayList<>();
        TreeSet<String> recipientSet = getRecipientSet();
        if (recipientSet == null) {
            recipientList.add(null);
        } else {
            recipientList.addAll(recipientSet);
        }
        return recipientList;
    }
    
    public final boolean isToPostmaster() {
        TreeSet<String> recipientSet = getRecipientSet();
        if (recipientSet == null) {
            return false;
        } else {
            for (String recipient : recipientSet) {
                if (recipient.startsWith("postmaster@")) {
                    return true;
                }
            }
            return false;
        }
    }
    
    public final boolean isRecipientAdmin() {
        TreeSet<String> recipientSet = getRecipientSet();
        if (recipientSet == null) {
            return false;
        } else {
            for (String recipient : recipientSet) {
                if (Core.isAdminEmail(recipient)) {
                    return true;
                }
            }
            return false;
        }
    }
    
    public abstract String getFrom();
    
    public final boolean isFromNotSigned() {
        String from = getFrom();
        if (from == null) {
            return false;
        } else if (isSigned(from)) {
            return false;
        } else if (sentByBULK()) {
            return false;
        } else {
            return SPF.getQualifier(getIP(), from, getHELO(), false) != Qualifier.PASS;
        }
    }
    
    public final boolean hasSuspectFrom() {
        String from = getFrom();
        TreeSet<String> recipientSet = getRecipientSet();
        if (from == null) {
            return false;
        } else if (from.isEmpty()) {
            return false;
        } else if (!from.contains("@")) {
            return false;
        } else if (isSigned(from)) {
            return false;
        } else if (recipientSet == null) {
            return false;
        } else {
            int index = from.indexOf('@');
            String domain = from.substring(index);
            for (String recipient : recipientSet) {
                if (recipient.endsWith(domain)) {
                    return true;
                }
            }
            return false;
        }
    }
    
    public final String getFromBlocked() {
        String from = getFrom();
        if (from == null) {
            return null;
        } else if (from.isEmpty()) {
            return null;
        } else if (!from.contains("@")) {
            return null;
        } else {
            String validation;
            if (isSigned(from)) {
                validation = "";
            } else if (sentByBULK()) {
                validation = ";BULK";
            } else {
                validation = ";NONE";
            }
            String userEmail = getUserEmail();
            String token = from + validation;
            if (Block.containsExact(token)) {
                return token;
            } else if (Block.containsExact(userEmail, token)) {
                return userEmail + ":" + token;
            } else {
                int index = from.indexOf('@');
                String host = from.substring(index);
                token = host + validation;
                if (Block.containsExact(token)) {
                    return token;
                } else if (Block.containsExact(userEmail, token)) {
                    return userEmail + ":" + token;
                } else {
                    host = '.' + host.substring(1);
                    do {
                        index = host.indexOf('.') + 1;
                        host = host.substring(index);
                        token = '.' + host + validation;
                        if (Block.containsExact(token)) {
                            return token;
                        } else if (Block.containsExact(userEmail, token)) {
                            return userEmail + ":" + token;
                        }
                    } while (host.contains("."));
                    return null;
                }
            }
        }
    }
    
    public abstract String getReplyTo();
    
    public abstract String getMessageID();
    
    public abstract String getQueueID();
    
    public abstract Date getDate();
    
    public abstract URL getUnsubscribe();
    
    public abstract String getSubject();
    
    public abstract Locale getLocale();
    
    public final boolean isRecipientPrivate() {
        TreeSet<String> recipientSet = getRecipientSet();
        if (recipientSet == null) {
            return false;
        } else {
            String userEmail = getUserEmail();
            for (String recipient : recipientSet) {
                if (Recipient.isPrivate(userEmail, recipient)) {
                    return true;
                }
            }
            return false;
        }
    }
    
    public final boolean isRecipientRestrict() {
        TreeSet<String> recipientSet = getRecipientSet();
        if (recipientSet == null) {
            return false;
        } else {
            String userEmail = getUserEmail();
            for (String recipient : recipientSet) {
                if (Recipient.isRestrict(userEmail, recipient)) {
                    return true;
                }
            }
            return false;
        }
    }
    
    public final Flag getRecipientFlag() {
        TreeSet<String> recipientSet = getRecipientSet();
        if (recipientSet == null) {
            return null;
        } else {
            boolean harmful = false;
            boolean undesirable = false;
            boolean unacceptable = false;
            boolean acceptable = false;
            boolean desirable = false;
            boolean beneficial = false;
            String userEmail = getUserEmail();
            for (String recipient : recipientSet) {
                Flag flag = Recipient.getFlag(userEmail, recipient);
                if (flag == HARMFUL) {
                    harmful = true;
                } else if (flag == UNDESIRABLE) {
                    undesirable = true;
                } else if (flag == UNACCEPTABLE) {
                    unacceptable = true;
                } else if (flag == ACCEPTABLE) {
                    acceptable = true;
                } else if (flag == DESIRABLE) {
                    desirable = true;
                } else if (flag == BENEFICIAL) {
                    beneficial = true;
                }
            }
            if (harmful && !desirable && !beneficial) {
                return HARMFUL;
            } else if (beneficial && !undesirable && !harmful) {
                return BENEFICIAL;
            } else if (undesirable && !desirable && !beneficial) {
                return UNDESIRABLE;
            } else if (desirable && !undesirable && !harmful) {
                return DESIRABLE;
            } else if (unacceptable && !acceptable) {
                return UNACCEPTABLE;
            } else {
                return ACCEPTABLE;
            }
        }
    }
    
    public final Flag getSubjectFlag() {
        if (isSenderMailerDeamon()) {
            return ACCEPTABLE;
        } else {
            Locale locale = getLocale();
            String subject = getSubject();
            String recipient = getRecipientList().get(0);
            Flag flag = Dictionary.getFlag(subject, locale, recipient);
            if (flag == BENEFICIAL && isQualifier(FAIL, SOFTFAIL)) {
                flag = DESIRABLE;
            }
            if (flag == BENEFICIAL || flag == DESIRABLE) {
                if (isRecipientSpoofing()) {
                    flag = ACCEPTABLE;
                }
            }
            return flag;
        }
    }
    
    public final String getSubjectFlagCause() {
        if (isSenderMailerDeamon()) {
            return null;
        } else {
            String subject = getSubject();
            String regex = Dictionary.getREGEX(subject);
            if (regex == null) {
                String ip = getIP();
                String helo = getHELO();
                String fqdn = getFQDN();
                String sender = getSender();
                Qualifier qualifier = getQualifier();
                String recipient = getRecipientList().get(0);
                boolean freemail = isSenderFreemail(); // Temporary.
                if (freemail && net.spfbl.data.SPF.isExtreme(sender, qualifier)) {
                    return null;
                } else if (!freemail && Reputation.isExtreme(ip, fqdn, helo, sender, qualifier)) {
                    return null;
                } else if (Dictionary.getFlag(subject, getLocale(), recipient) == null) {
                    return null;
                } else {
                    return "REPUTATION";
                }
            } else {
                return regex;
            }
        }
    }
    
    public final boolean isRecipientAbuse() {
        TreeSet<String> recipientSet = getRecipientSet();
        if (recipientSet == null) {
            return false;
        } else {
            for (String recipient : recipientSet) {
                if (Core.isAbuseEmail(recipient)) {
                    return true;
                } else if (Recipient.isAbuse(getUserEmail(), recipient)) {
                    return true;
                }
            }
            return false;
        }
    }
    
    public final boolean isRecipientHacked() {
        TreeSet<String> recipientSet = getRecipientSet();
        if (recipientSet == null) {
            return false;
        } else {
            for (String recipient : recipientSet) {
                if (Recipient.isHacked(getUserEmail(), recipient)) {
                    return true;
                }
            }
            return false;
        }
    }
    
    public abstract boolean isFilter(Filter... filter);
    
    public abstract String getMalware();
    
    public abstract TreeSet<String> getExecutableSet();
    
    public final int usingSince() {
        Integer usingSince = net.spfbl.data.Domain.usingSinceNewest(
                getHELO(), getFQDN(), getSender(), getFrom(), getReplyTo()
        );
        if (usingSince == null) {
            return -1;
        } else {
            return usingSince;
        }
    }
    
    public abstract String getInReplyTo();
    
    public boolean inReplyToContainsRecipient() {
        String inReplyTo = getInReplyTo();
        TreeSet<String> recipientSet = getRecipientSet();
        if (inReplyTo == null) {
            return false;
        } else if (recipientSet == null) {
            return false;
        } else {
            for (String recipient : recipientSet) {
                if (inReplyTo.contains(getEmailHostname(recipient))) {
                    return true;
                }
            }
            return false;
        }
    }
    
    public abstract TreeSet<String> getSignerSet();
    
    public final boolean isSigned(String address) {
        return isSigned(address, false);
    }
    
    public final boolean isNotSigned(String address) {
        return isNotSigned(address, false);
    }
    
    public final boolean isSigned(String address, boolean checkSPF) {
        Boolean signed = isSignedUndefined(address, checkSPF);
        return Objects.equals(signed, true);
    }
    
    public final boolean isNotSigned(String address, boolean checkSPF) {
        Boolean signed = isSignedUndefined(address, checkSPF);
        return Objects.equals(signed, false);
    }
    
    private Boolean isSignedUndefined(String address, boolean checkSPF) {
        if (address == null) {
            return null;
        } else {
            TreeSet<String> signerSet = getSignerSet();
            int index = address.indexOf('@') + 1;
            String domain = address.substring(index);
            if (signerSet != null && containsSigner(domain, signerSet)) {
                return true;
            } else if (isPass() && getSender().endsWith('@' + domain)) {
                return true;
            } else if ((domain = Domain.extractDomainSafe(domain, false)) == null) {
                return false;
            } else if (domain.equals(extractRootDomainFQDN())) {
                return true;
            } else if (signerSet != null && containsSigner(domain, signerSet)) {
                return true;
            } else if (isPass() && getSender().endsWith('@' + domain)) {
                return true;
            } else if (checkSPF && SPF.getQualifier(getIP(), address, getHELO(), false) == Qualifier.PASS) {
                return true;
            } else if (signerSet == null) {
                return null;
            } else {
                return false;
            }
        }
    }
    
    public final boolean isSenderFreemail() {
        if (getSender() == null) {
            return false;
        } else {
            return Provider.isFreeMail(getSender()) && isSigned(getSender());
        }
    }
    
    public final boolean isHarmful() {
        if (isSenderFreemail()) {
            return Reputation.isHarmful(
                    getIP(), getFQDN(), getHELO(),
                    getSender(), getQualifier(),
                    null, null
            );
        } else {
            return Reputation.isHarmful(
                    getIP(), getFQDN(), getHELO(),
                    getSender(), getQualifier(),
                    getFrom(), getSignerSet()
            );
        }
    }
    
    public final boolean isUndesirable() {
        if (isSenderFreemail()) {
            return Reputation.isUndesirable(
                    getIP(), getFQDN(), getHELO(),
                    getSender(), getQualifier(),
                    null, null
            );
        } else {
            return Reputation.isUndesirable(
                    getIP(), getFQDN(), getHELO(),
                    getSender(), getQualifier(),
                    getFrom(), getSignerSet()
            );
        }
    }
    
    public final boolean isDesirable() {
        if (isSenderFreemail()) {
            return Reputation.isDesirable(
                    getIP(), getFQDN(), getHELO(),
                    getSender(), getQualifier(),
                    null, null
            );
        } else {
            return Reputation.isDesirable(
                    getIP(), getFQDN(), getHELO(),
                    getSender(), getQualifier(),
                    getFrom(), getSignerSet()
            );
        }
    }
    
    public final String getSpoofingSender() {
        Qualifier qualifier = getQualifier();
        if (qualifier == PASS) {
            return null;
        } else {
            String sender = getSender();
            if (sender == null) {
                return null;
            } else if (!sender.contains("@")) {
                return null;
            } else if (isSigned(sender)) {
                return null;
            } else {
                int index = sender.indexOf('@');
                String domain = sender.substring(index);
                if (Ignore.containsExact(domain)) {
                    return domain;
                } else {
                    return null;
                }
            }
        }
        
    }
    
    public final String getSpoofingFrom() {
        String from = getFrom();
        String fqdn = getFQDN();
        if (from == null) {
            return null;
        } else if (from.isEmpty()) {
            return null;
        } else if (!from.contains("@")) {
            return null;
        } else if (isSigned(from)) {
            return null;
        } else if (Provider.containsFQDN(fqdn)) {
            return null;
        } else if (Ignore.containsFQDN(fqdn)) {
            return null;
        } else {
            int index = from.indexOf('@');
            String domain = from.substring(index);
            String sender = getSender();
            if (sender != null && isPass() && sender.endsWith('.' + domain.substring(1))) {
                return null;
            } else if (Ignore.containsExact(domain)) {
                return domain;
            } else if (NoReply.containsExact(domain) && Block.containsExact(domain + ";NONE")) {
                return domain + ";NONE";
            } else if (Ignore.containsFQDN(domain.substring(1)) && isFromUnroutable()) {
                return domain.substring(1);
            } else {
                return null;
            }
        }
    }
    
    public final boolean isSpoofingFQDN() {
        String client = getClient();
        String helo = getHELO();
        if (client == null) {
            return false;
        } else if (helo == null) {
            return false;
        } else {
            String fqdn = getFQDN();
            return client.equals(helo) && !client.equals(fqdn);
        }
    }
    
    public final boolean hasMalwareNotIgnored() {
        String userEmail = getUserEmail();
        String malware = getMalware();
        if (userEmail == null) {
            return false;
        } else if (malware == null) {
            return false;
        } else if (Ignore.containsExact(userEmail + ":MALWARE=" + malware)) {
            return false;
        } else {
            return true;
        }
    }
    
    public abstract TreeSet<String> getLinkSet();
    
    public final boolean hasPhishingBlocked() {
        return getPhishingBlocked() != null;
    }

    public final String getPhishingBlocked() {
        TreeSet<String> linkSet = getLinkSet();
        if (linkSet == null) {
            return null;
        } else if (linkSet.isEmpty()) {
            return null;
        } else {
            for (String link : linkSet) {
                if (Core.isSignatureURL(link)) {
                    if (Block.containsExact(link)) {
                        return link;
                    }
                } else if (isValidIP(link)) {
                    if (Block.containsExact("HREF=" + link)) {
                        return "HREF=" + link;
                    }
                } else if (isHostname(link)) {
                    String url = "http://" + link + "/";
                    String signature = Core.getSignatureURL(url);
                    if (Block.containsExact(signature)) {
                        return signature;
                    }
                }
            }
            return null;
        }
    }
    
    public final String getTrueSender() {
        String sender = getSender();
        String from = getFrom();
        String replyto = getReplyTo();
        if (isSigned(from) && isValidEmail(from)) {
            return from;
        } else if (isSigned(replyto) && isValidEmail(replyto)) {
            return replyto;
        } else if (sender == null) {
            return from == null ? replyto : from;
        } else if (sender.endsWith("@gmail.com") && sender.contains("+caf_=")) {
            return Domain.normalizeEmail(sender);
        } else if (Provider.isFreeMail(sender) && isValidEmail(sender)) {
            return sender;
        } else if (Provider.containsDomain(getFQDN()) && isValidEmail(sender) && !Provider.containsDomain(sender)) {
            return sender;
        } else if (Provider.containsDomain(getFQDN()) && isValidEmail(from) && !Provider.containsDomain(from)) {
            return from;
        } else if (Provider.containsDomain(getFQDN()) && isValidEmail(from) && Provider.containsDomain(sender)) {
            return from;
        } else if (isSigned(sender) && isValidEmail(from) && Provider.containsDomain(sender)) {
            return from;
        } else if (Provider.containsDomain(getFQDN()) && isValidEmail(replyto) && !Provider.containsDomain(replyto)) {
            return replyto;
       } else if (isValidEmail(sender)) {
            return sender;
        } else if (isValidEmail(from)) {
            return from;
        } else if (isValidEmail(replyto)) {
            return replyto;
        } else if (Domain.isMailFrom(sender)) {
            if (sender.startsWith("srs0=") || sender.startsWith("srs0+")) {
                int index1 = sender.lastIndexOf('@');
                int index2 = sender.lastIndexOf('=', index1);
                if (index2 > 0) {
                    int index3 = sender.lastIndexOf('=', index2-1);
                    if (index3 > 0) {
                        String part = sender.substring(index2+1, index1);
                        String domain = sender.substring(index3+1, index2);
                        return part + '@' + domain;
                    }
                }
            }
            return sender;
        } else if (Domain.isMailFrom(from)) {
            return from;
        } else if (Domain.isMailFrom(replyto)) {
            return replyto;
        } else {
            return sender;
        }
    }
    
    public enum Situation {
        NONE,
        ORIGIN,
        IP,
        ZONE,
        AUTHENTIC,
        BULK,
        SAME,
        DOMAIN,
        RECIPIENT,
        MALWARE,
        ALL
    }
    
    public final String getQualifierResult() {
        Qualifier qualifier = getQualifier();
        if (qualifier == null) {
            return "none";
        } else {
            return qualifier.getResult();
        }
    }
    
    public final String getQualifierName() {
        String trueSender = getTrueSender();
        Qualifier qualifier = getQualifier();
        if (trueSender == null) {
            return "NONE";
        } else if (isSigned(trueSender)) {
            return "PASS";
        } else if (qualifier == null) {
            return "NONE";
        } else if (trueSender.equals(getSender())) {
            return qualifier.name();
        } else {
            return "NONE";
        }
    }
    public final boolean sentByBULK() {
        if (isFail()) {
            return false;
        } else if (Provider.containsIPorFQDN(getIP())) {
            return true;
        } else {
            String fqdn = getFQDN();
            return Provider.containsDomain(fqdn);
        }
    }
    
    public final String getValidator(boolean authentic) {
        String sender = getSender();
        if (sender == null) {
            return null;
        } else if (sender.isEmpty()) {
            return null;
        } else if (authentic && getQualifierName().equals("PASS")) {
            return "PASS";
        } else if (!Provider.isFreeMail(sender) && sentByBULK()) {
            return "BULK";
        } else {
            String domain = extractRootDomainFQDN();
            if (domain == null) {
                return getIP();
            } else {
                return domain;
            }
        }
    }
    
    public final Situation getSituation(boolean authentic) {
        String validator = getValidator(true);
        if (validator == null) {
            return Situation.ORIGIN;
        } else if (authentic && validator.equals("PASS")) {
            return Situation.AUTHENTIC;
        } else if (validator.equals("BULK")) {
            return Situation.BULK;
        } else if (isValidIP(validator)) {
            return Situation.IP;
        } else {
            return Situation.ZONE;
        }
    }
    
    public final String getSenderSimplified(boolean byDomain, boolean pontuacao) {
        String trueSender = getTrueSender();
        if (trueSender == null) {
            return null;
        } else if (trueSender.isEmpty()) {
            return null;
        } else if (!trueSender.contains("@")) {
            return null;
        } else if (trueSender.startsWith("mailer-daemon@")) {
            return trueSender;
        } else if (Provider.isFreeMail(trueSender)) {
            if (byDomain && isNotSigned(trueSender) && !sentByBULK()) {
                int index = trueSender.indexOf('@');
                return trueSender.substring(index);
            } else if (isValidEmail(trueSender)) {
                return Domain.normalizeEmail(trueSender);
            } else {
                int index = trueSender.indexOf('@');
                return trueSender.substring(index);
            }
        } else if (byDomain) {
            int index = trueSender.indexOf('@');
            String senderDomain = trueSender.substring(index);
            String domain = Domain.extractDomainSafe(
                    senderDomain.substring(1), true
            );
            if (domain == null || Provider.containsExact(domain)) {
                return senderDomain;
            } else if (pontuacao) {
                return domain;
            } else {
                return domain.substring(1);
            }
        } else {
            int index = trueSender.indexOf('@');
            return trueSender.substring(index);
        }
    }
    
    public final String getWhiteSender() {
        Situation situation;
        String senderLocal = getTrueSender();
        if (senderLocal == null) {
            return null;
        } else if (senderLocal.isEmpty()) {
            return null;
        } else if (isSigned(senderLocal)) {
            situation = Situation.AUTHENTIC;
        } else if (senderLocal.equals(getSender())) {
            situation = getSituation(true);
        } else if (!Provider.isFreeMail(senderLocal) && sentByBULK()) {
            situation = Situation.BULK;
        } else {
            situation = getSituation(false);
        }
        String domain;
        switch (situation) {
            case IP:
                return getSenderSimplified(false, true) + ";" + getIP();
            case ZONE:
                domain = extractRootDomainFQDN();
                if (domain == null) {
                    return null;
                } else {
                    return getSenderSimplified(false, true) + ";" + domain;
                }
            case AUTHENTIC:
                return getSenderSimplified(false, true) + ";PASS";
            case BULK:
                return getSenderSimplified(false, true) + ";BULK";
            case SAME:
                String validator = getValidator(false);
                if (validator == null) {
                    return null;
                } else {
                    return getSenderSimplified(false, true) + ";" + validator;
                }
            default:
                return null;
        }
    }
    
    public final String getWhiteKey() {
        String key = getWhiteSender();
        if (key == null) {
            key = extractRootDomainFQDN();
            if (key == null) {
                key = getFQDN();
                if (key == null) {
                    key = "mailer-daemon@;" + getIP();
                } else {
                    key = "mailer-daemon@" + key;
                }
            } else {
                key = "mailer-daemon@" + key;
            }
        }
        return key;
    }
    
    public final boolean isWhiteKeyByAdmin() {
        String email = Core.getAdminEmail();
        if (email == null) {
            return false;
        } else {
            String whiteKey = getWhiteKey();
            return White.containsExtact(email, whiteKey);
        }
    }
    
    public final String getOriginDomain(boolean pontuacao) {
        String host = getFQDN();
        if (host == null) {
            host = getHELO();
        }
        try {
            return Domain.extractDomain(host, pontuacao);
        } catch (ProcessException ex) {
            return null;
        }
    }
    
    public final String getSenderDomain(boolean pontuacao) {
        String trueSender = getTrueSender();
        if (trueSender == null) {
            return extractRootDomainFQDN();
        } else if (trueSender.isEmpty()) {
            return extractRootDomainFQDN();
        } else {
            int index = trueSender.indexOf('@');
            try {
                String host = trueSender.substring(index + 1);
                return Domain.extractDomain(host, pontuacao);
            } catch (ProcessException ex) {
                if (pontuacao) {
                    return '.' + trueSender.substring(index);
                } else {
                    return trueSender.substring(index);
                }
            }
        }
    }
    
    public final String getBlockSender() {
        Situation situation;
        String trueSender = getTrueSender();
        if (trueSender == null) {
            return null;
        } else if (trueSender.isEmpty()) {
            return null;
        } else if (!trueSender.contains("@")) {
            return null;
        } else if (isSigned(trueSender)) {
            situation = Situation.AUTHENTIC;
        } else if (trueSender.equals(getSender())) {
            situation = getSituation(true);
        } else if (!Provider.isFreeMail(trueSender) && sentByBULK()) {
            situation = Situation.BULK;
        } else {
            situation = Situation.NONE;
        }
        switch (situation) {
            case AUTHENTIC:
                return getSenderSimplified(true, true);
            case BULK:
                return getSenderSimplified(true, true) + ";BULK";
            case NONE:
                String domain1 = getOriginDomain(false);
                String sender1 = getSenderSimplified(true, true);
                if (sender1 == null && domain1 == null) {
                    return "@;" + getIP();
                } else if (sender1 == null) {
                    return "@;" + domain1;
                } else if (domain1 == null) {
                    return sender1 + ";NONE";
                } else if (sender1.equals('.' + domain1)) {
                    return sender1;
                } else {
                    return sender1 + ";" + domain1;
                }
            case ZONE:
                String domain2 = getOriginDomain(false);
                String sender2 = getSenderDomain(true);
                if (sender2 == null && domain2 == null) {
                    return "@;" + getIP();
                } else if (sender2 == null) {
                    return "@;" + domain2;
                } else if (domain2 == null) {
                    return sender2 + ";NOTPASS";
                } else if (sender2.equals('.' + domain2)) {
                    return sender2;
                } else {
                    return sender2 + ";" + domain2;
                }
            case IP:
                return getSenderDomain(true) + ";NOTPASS";
            case SAME:
                String validator = getValidator(false);
                if (validator == null) {
                    return getSenderSimplified(true, true);
                } else {
                    return getSenderSimplified(true, true) + ";" + validator;
                }
            case DOMAIN:
                String senderSimplified = getSenderSimplified(true, true);
                if (senderSimplified == null) {
                    return null;
                } else {
                    return senderSimplified;
                }
            case ORIGIN:
            case ALL:
                String domain3 = getOriginDomain(false);
                if (domain3 == null) {
                    return "mailer-daemon@;" + getIP();
                } else {
                    return "mailer-daemon@" + domain3;
                }
            default:
                return null;
        }
    }
    
    public final boolean white() {
        String userEmail = getUserEmail();
        String blockKey = getBlockKey();
        return White.addExact(userEmail, blockKey);
    }
    
    public final boolean block() {
        String userEmail = getUserEmail();
        String blockKey = getBlockKey();
        return Block.addExact(userEmail, blockKey);
    }
    
    public final String getBlockKey() {
        String key = getBlockSender();
        if (key == null) {
            key = extractRootDomainFQDN();
            if (key == null) {
                key = getFQDN();
                if (key == null) {
                    key = "mailer-daemon@;" + getIP();
                } else {
                    key = "mailer-daemon@" + key;
                }
            } else {
                key = "mailer-daemon@" + key;
            }
        }
        return key;
    }
    
    public final boolean isBlockKeyByAdmin() {
        String email = Core.getAdminEmail();
        if (email == null) {
            return false;
        } else {
            String blockKey = getBlockKey();
            return Block.containsExact(email, blockKey);
        }
    }
    
    public final boolean isTrustedMailerDaemon() {
        String ip = getIP();
        if (!isSenderMailerDeamon()) {
            return false;
        } else if (Provider.containsIPorFQDN(ip)) {
            return true;
        } else if (Ignore.containsIPorFQDN(ip)) {
            return true;
        } else if (White.containsIPorFQDN(ip)) {
            return true;
        } else {
            return Reputation.isDesirable(ip, getFQDN());
        }
    }
    
    public final boolean isWhiteKey() {
        return White.containsExtact(
                getUserEmail(), getWhiteKey()
        );
    }
    
    public final String getWhite() {
        if (isWhiteKey()) {
            return getWhiteKey();
        } else {
            String userEmail = getUserEmail();
            String ip = getIP();
            String fqdn = getFQDN();
            String sender = getSender();
            String from = getFrom();
            String replyto = getReplyTo();
            Qualifier qualifier = getQualifier();
            String white;
            for (String recipient : getRecipientList()) {
                if (sender != null && (white = White.find(userEmail, ip, sender, fqdn, (isSigned(sender) ? "PASS" : qualifier == null ? "NONE" : qualifier.name()), recipient)) != null) {
                    return white;
                } else if (from != null && (white = White.find(userEmail, ip, from, fqdn, (isSigned(from) ? "PASS" : "NONE"), recipient)) != null) {
                    return white;
                } else if (replyto != null && (white = White.find(userEmail, ip, replyto, fqdn, (isSigned(replyto) ? "PASS" : "NONE"), recipient)) != null) {
                    return white;
                } else if (sender == null) {
                    return White.find(userEmail, ip, null, fqdn, "NONE", recipient);
                }
            }
            return null;
        }
    }
    
    public final boolean isBlockKey() {
        return Block.containsExact(
                getUserEmail(), getBlockKey()
        );
    }
    
    public final String getBlock() {
        String userEmail = getUserEmail();
        String block;
        if (isBlockKey()) {
            return getBlockKey();
        } else {
            String ip = getIP();
            String fqdn = getFQDN();
            String sender = getSender();
            String from = getFrom();
            String replyto = getReplyTo();
            Qualifier qualifier = getQualifier();
            for (String recipient : getRecipientList()) {
                if (sender != null && (block = Block.find(userEmail, ip, sender, fqdn, (isSigned(sender) ? "PASS" : qualifier == null ? "NONE" : qualifier.name()), recipient, false, false, false, false, true, true)) != null) {
                    return block;
                } else if (from != null && (block = Block.find(userEmail, ip, from, fqdn, (isSigned(from) ? "PASS" : "NONE"), recipient, false, false, false, false, true, true)) != null) {
                    return block;
                } else if (replyto != null && (block = Block.find(userEmail, ip, replyto, fqdn, (isSigned(replyto) ? "PASS" : "NONE"), recipient, false, false, false, false, true, true)) != null) {
                    return block;
                } else if (sender == null && (block = Block.find(userEmail, ip, null, fqdn, "NONE", recipient, false, false, false, false, true, true)) != null) {
                    return block;
                }
            }
        }
        if ((block = Block.getWHOIS(userEmail, getTrueSender())) != null) {
            return block;
        } else {
            return getListedDNSBL();
        }
    }
    
    public final String getListedDNSBL() {
        if (Ignore.containsHost(getFQDN())) {
            return null;
        } else if (Provider.containsDomain(getFQDN())) {
            return null;
        } else {
            return Block.findDNSBL(getIP());
        }
    }
    
    public abstract boolean isInvitation();
    
    public abstract boolean isForgedFrom();
    
    public abstract boolean isSpoofedRecipient();
    
    public boolean isRecipientSpoofing() {
        String from = getFrom();
        if (from == null) {
            return false;
        } else if (from.contains(getRecipientHostname(false))) {
            return isNotSigned(from);
        } else {
            return false;
        }
    }
    
    public boolean isWhite() {
        if (isInvitation()) {
            return true;
        } else {
            return getWhite() != null;
        }
    }
    
    public final String getWhiteReason() {
        if (isInvitation()) {
            return "INVITATION";
        } else {
            return getWhite();
        }
    }
    
    public final boolean hasExecutableBlocked() {
        String userEmail = getUserEmail();
        TreeSet<String> executableSet = getExecutableSet();
        if (userEmail == null) {
            return false;
        } else if (executableSet == null) {
            return false;
        } else if (executableSet.isEmpty()) {
            return false;
        } else {
            for (String signature : executableSet) {
                if (!Ignore.containsExact(userEmail + ":" + signature)) {
                    if (Block.containsExact(signature)) {
                        return true;
                    }
                }
            }
            return false;
        }
    }
    
    public final boolean hasExecutableNotIgnored() {
        String userEmail = getUserEmail();
        TreeSet<String> executableSet = getExecutableSet();
        if (userEmail == null) {
            return false;
        } else if (executableSet == null) {
            return false;
        } else if (executableSet.isEmpty()) {
            return false;
        } else {
            int count = executableSet.size();
            for (String signature : executableSet) {
                if (Ignore.containsExact(userEmail + ":" + signature)) {
                    count--;
                }
            }
            return count > 0;
        }
    }
    
    public final boolean hasExecutable() {
        TreeSet<String> executableSet = getExecutableSet();
        if (executableSet == null) {
            return false;
        } else {
            return !executableSet.isEmpty();
        }
    }
    
    public final String getAnyLinkSuspect(boolean findIP) {
        TreeSet<String> linkSet = getLinkSet();
        if (linkSet == null) {
            return null;
        } else {
            for (String token : linkSet) {
                if (Core.isSignatureURL(token)) {
                    if (Block.containsExact(token)) {
                        return token;
                    }
                } else if (token.endsWith(".http")) {
                    Server.logError(token); // Temporary
                    return null;
                } else if (token.endsWith(".https")) {
                    Server.logError(token); // Temporary
                    return null;
                }
                String block;
                if ((block = Block.findHREF(null, getUserEmail(), token, findIP)) != null) {
                    return block;
                } else if (isHostname(token)) {
                    String domain = Domain.extractDomainSafe(token, true);
                    if (NoReply.containsExact(domain)) {
                        return domain + ";NOTCOMPLIANCE";
                    } else {
                        return null;
                    }
                }
            }
            return null;
        }
    }
    
    public final boolean isSenderNXDOMAIN() {
        String sender = getSender();
        if (sender == null) {
            return false;
        } else if (sender.isEmpty()) {
            return false;
        } else {
            SPF spf = SPF.getSPF(sender);
            if (spf == null) {
                return false;
            } else if (spf.isDefinitelyInexistent()) {
                int index = sender.indexOf('@');
                String domain = sender.substring(index);
                NoReply.addSafe(domain);
                if (Block.tryAdd(domain + ";NONE")) {
                    Server.logDebug(null, "new BLOCK '" + domain + ";NONE' added by 'NXDOMAIN'.");
                }
                return true;
            } else {
                return false;
            }
        }
    }

    public final boolean isFromNXDOMAIN() {
        String from = getFrom();
        if (from == null) {
            return false;
        } else if (from.isEmpty()) {
            return false;
        } else {
            SPF spf = SPF.getSPF(from);
            if (spf == null) {
                return false;
            } else if (spf.isDefinitelyInexistent()) {
                int index = from.indexOf('@');
                String domain = from.substring(index);
                NoReply.addSafe(domain);
                if (Block.tryAdd(domain + ";NONE")) {
                    Server.logDebug(null, "new BLOCK '" + domain + ";NONE' added by 'NXDOMAIN'.");
                }
                return true;
            } else {
                return false;
            }
        }
    }
    
    public final Flag getFlagSPF(String sender, Qualifier qualifier) {
        if (sender == null) {
            return null;
        } else {
            int index = sender.indexOf('@');
            String domain = sender.substring(index + 1);
            Flag flag = net.spfbl.data.SPF.getFlag(sender, qualifier);
            if (qualifier == PASS) {
                return flag;
            } else if (Ignore.containsExact('@' + domain) && !isSigned(sender, true)) {
                return HARMFUL; // Critical spoofing case.
            } else {
                return flag;
            }
        }
    }
    
    public final Flag getFlagEnvelope() {
        String ip = getIP();
        String helo = getHELO();
        String fqdn = getFQDN();
        String sender = getSender();
        Qualifier qualifier = getQualifier();
        String userEmail = getUserEmail();
        String recipient = getRecipientFirst();
        Flag cidrFlag = CIDR.getFlag(ip);
        Flag heloFlag = Generic.getFlag(helo);
        Flag fqdnFlag = FQDN.getFlag(fqdn);
        Flag abuseFlag = Abuse.getFlag(ip,fqdn);
        Flag senderFlag = net.spfbl.data.SPF.getFlag(
                sender, qualifier
        );
        Flag recipientFlag = Recipient.getFlag(
                userEmail, recipient
        );
        return NeuralNetwork.getFlagEnvelope(
                cidrFlag, heloFlag, fqdnFlag,
                abuseFlag, senderFlag, recipientFlag
        );
    }
    
    public final Flag getFlagDKIM(String from, TreeSet<String> signerSet) {
        if (from == null) {
            return null;
        } else if (signerSet == null) {
            return isSigned(from) ? ACCEPTABLE : UNACCEPTABLE;
        } else if (Provider.isFreeMail(from)) {
            int index = from.lastIndexOf('@') + 1;
            String domain = from.substring(index);
            return signerSet.contains(domain) ? ACCEPTABLE : UNACCEPTABLE;
        } else {
            return DKIM.getFlag(from, signerSet, isSigned(from, true));
        }
    }
    
    public final Flag getFlagCIDR() {
        String ip = getIP();
        return getFlagCIDR(ip);
    }
    
    public final Flag getFlagCIDR(String ip) {
        if (isPass() && isEnvelopeFreeMail()) {
            return Flag.ACCEPTABLE;
        } else {
            return CIDR.getFlag(ip);
        }
    }
    
    public final Flag getFlagAbuse() {
        if (isPass() && isEnvelopeFreeMail()) {
            return Flag.ACCEPTABLE;
        } else {
            String abuse = getAbuseOrigin();
            if (abuse == null) {
                return UNDESIRABLE;
            } else {
                Flag flag = Abuse.getFlag(abuse);
                if (flag == BENEFICIAL && NoReply.isUnsubscribed(abuse)) {
                    flag = DESIRABLE;
                } else if (flag == HARMFUL && Ignore.containsExact(abuse)) {
                    flag = UNDESIRABLE;
                }
                return flag;
            }
        }
    }
    
    public final Flag getFlagFQDN() {
        if (isPass() && isEnvelopeFreeMail()) {
            return Flag.ACCEPTABLE;
        } else {
            Flag flag = FQDN.getFlag(getFQDN());
            if (flag == null) {
                return Flag.UNACCEPTABLE;
            } else if (flag == BENEFICIAL && sentByBULK()) {
                return DESIRABLE;
            } else {
                return flag;
            }
        }
    }
    
    public static Boolean isSigned(
            Qualifier qualifier, String sender, String fqdn,
            String email, TreeSet<String> signerSet
    ) {
        if (signerSet == null) {
            return null;
        } else {
            int index = email.indexOf('@') + 1;
            String domain = email.substring(index);
            if (containsSigner(domain, signerSet)) {
                return true;
            } else if (qualifier == PASS && sender.endsWith('@' + domain)) {
                return true;
            } else if ((domain = Domain.extractDomainSafe(domain, false)) == null) {
                return false;
            } else if (domain.equals(Domain.extractDomainSafe(fqdn, false))) {
                return true;
            } else if (containsSigner(domain, signerSet)) {
                return true;
            } else if (qualifier == PASS && sender.endsWith('@' + domain)) {
                return true;
            } else {
                return false;
            }
        }
    }
    
    public static Boolean containsSigner(
            String domain, TreeSet<String> signerSet
    ) {
        if (domain == null) {
            return false;
        } else if (signerSet == null) {
            return null;
        } else {
            return signerSet.contains(domain);
        }
    }
    
    public final boolean isFromUnroutable() {
        String from = getFrom();
        if (from == null) {
            return false;
        } else if (Provider.isFreeMail(from)) {
            return false;
        } else {
            int index = from.indexOf('@') + 1;
            String domain = from.substring(index);
            if (domain.length() == 0) {
                return false;
            } else if (Ignore.containsExact('@' + domain)) {
                return false;
            } else if (Provider.containsExact('.' + domain)) {
                return false;
            } else if (Ignore.containsHost(domain)) {
                return false;
            } else if (net.spfbl.data.Domain.usingSinceInt(domain) > 14) {
                return false;
            } else {
                try {
                    ArrayList<String> mxSet = Reverse.getMXSet(domain, false);
                    if (mxSet == null) {
                        return true;
                    } else if (mxSet.isEmpty()) {
                        return true;
                    } else {
                        int validRouteCount = 0;
                        for (String mx : mxSet) {
                            for (String ip : Reverse.getAddressSetSafe(mx)) {
                                if (!Subnet.isReservedIP(ip)) {
                                    validRouteCount++;
                                }
                            }
                        }
                        return validRouteCount == 0;
                    }
                } catch (ServiceUnavailableException | CommunicationException ex) {
                    // Inconclusive.
                    return false;
                } catch (NamingException ex) {
                    return true;
                }
            }
        }
    }
    
    public boolean isBanned() {
        String userEmail = getUserEmail();
        String ip = getIP();
        String helo = getHELO();
        String fqdn = getFQDN();
        String sender = getSender();
        Qualifier qualifier = getQualifier();
        for (String recipient : getRecipientList()) {
            if (Block.isBanned(
                    userEmail, ip, helo, fqdn, sender,
                    qualifier == null ? "NONE" : qualifier.name(),
                    recipient
            )) {
                return true;
            }
        }
        return false;
    }
    
    public String getBannedKey() {
        String userEmail = getUserEmail();
        String ip = getIP();
        String helo = getHELO();
        String fqdn = getFQDN();
        String sender = getSender();
        Qualifier qualifier = getQualifier();
        for (String recipient : getRecipientList()) {
            String domain = simplifyEmail(
                    recipient
            );
            String blockKey = Block.keyBlockKey(
                    userEmail, ip, helo, fqdn,
                    sender, qualifier, domain
            );
            if (blockKey != null) {
                return blockKey;
            }
        }
        return null;
    }
    
    public enum Filter {
        ORIGIN_WHITE_KEY_USER,
        ORIGIN_BLOCK_KEY_USER,
        RECIPIENT_ABUSE,
        FQDN_SPOOFED,
        MALWARE_NOT_IGNORED,
        MALWARE_IGNORED,
        RECIPIENT_INEXISTENT,
        ORIGIN_WHITE_KEY_ADMIN,
        ORIGIN_BLOCK_KEY_ADMIN,
        FROM_SPOOFED_RECIPIENT,
        FROM_NOT_SIGNED,
        SENDER_MAILER_DEAMON_TRUSTED,
        ORIGIN_WHITELISTED,
        ORIGIN_BANNED,
        DKIM_HARMFUL,
        DKIM_UNDESIRABLE,
        FROM_NXDOMAIN,
        SENDER_NXDOMAIN,
        BULK_BENEFICIAL,
        FROM_SPOOFED_SENDER,
        IN_REPLY_TO_EXISTENT,
        IN_REPLY_TO_DESIRABLE,
        FROM_SUSPECT,
        PHISHING_BLOCKED,
        EXECUTABLE_BLOCKED,
        SUBJECT_HARMFUL,
        IP_DYNAMIC,
        HELO_ANONYMOUS,
        FQDN_DESIRABLE,
        SENDER_MAILER_DEAMON,
        SPF_FAIL,
        SPF_SPOOFING,
        CIDR_BENEFICIAL,
        RECIPIENT_POSTMASTER,
        SENDER_RED,
        SENDER_INVALID,
        SPF_DESIRABLE,
        DKIM_DESIRABLE,
        FROM_BLOCKED,
        EXECUTABLE_UNDESIRABLE,
        EXECUTABLE_NOT_IGNORED,
        FROM_FORGED,
        SUBJECT_BENEFICIAL,
        ABUSE_BENEFICIAL,
        SPF_HARMFUL,
        FQDN_BENEFICIAL,
        FROM_ABSENT,
        DKIM_BENEFICIAL,
        SPF_BENEFICIAL,
        FROM_UNROUTABLE,
        ORIGIN_BLOCKED,
        SUBJECT_UNDESIRABLE,
        HREF_UNDESIRABLE,
        HREF_SUSPECT,
        FQDN_RED,
        ABUSE_HARMFUL,
        SPF_UNDESIRABLE,
        FQDN_HARMFUL,
        FQDN_UNDESIRABLE,
        CIDR_HARMFUL,
        DOMAIN_EMERGED,
        SPF_SOFTFAIL,
        BULK_BOUNCE,
        SPF_NXDOMAIN,
        HOLD_WHITE_KEY_USER,
        HOLD_BLOCK_KEY_USER,
        HOLD_WHITELISTED,
        HOLD_WHITE_KEY_ADMIN,
        HOLD_BANNED,
        HOLD_BLOCK_KEY_ADMIN,
        HOLD_SPF_FAIL,
        HOLD_SPF_SOFTFAIL,
        HOLD_BLOCKED,
        HOLD_UNDESIRABLE,
        HOLD_DOMAIN_EMERGED,
        HOLD_HREF_SUSPECT,
        HOLD_EXPIRED,
        HOLD_ENVELOPE_UNDESIRABLE,
        RECIPIENT_HARMFUL,
        RECIPIENT_BENEFICIAL,
        RECIPIENT_UNDESIRABLE,
        RECIPIENT_DESIRABLE,
        ABUSE_SUBMISSION,
        ENVELOPE_BLOCKED,
        ENVELOPE_INVALID,
        FQDN_PROVIDER,
        ORIGIN_UNDESIRABLE,
        ORIGIN_HARMFUL,
        ABUSE_BLOCKED,
        SUBJECT_DESIRABLE,
        HOLD_RECIPIENT_UNDESIRABLE,
        USER_PHISHING,
        USER_SPAM,
        RECIPIENT_PRIVATE,
        RECIPIENT_RESTRICT,
        FROM_ESSENTIAL,
        SENDER_ESSENTIAL,
        FQDN_ESSENTIAL,
        HOLD_RECIPIENT_RESTRICT,
        HOLD_ENVELOPE_BLOCKED,
        HOLD_SENDER_RED,
        HOLD_FQDN_RED,
        FROM_FREEMAIL,
        ENVELOPE_HARMFUL,
        ENVELOPE_UNDESIRABLE,
        ENVELOPE_BENEFICIAL,
        ENVELOPE_DESIRABLE,
        RECIPIENT_SPOOFING,
        SENDER_SPOOFING,
        DOMAIN_INEXISTENT,
        RECIPIENT_HACKED
    }
    
    public static Filter tryToGetFilter(String name) {
        if (name == null) {
            return null;
        } else {
            try {
                int index = name.indexOf(';');
                if (index > 0) {
                    return Filter.valueOf(name.substring(0, index));
                } else {
                    return Filter.valueOf(name);
                }
            } catch (IllegalArgumentException ex) {
                return null;
            }
        }
    }
    
    public final Filter processFilter() {
        SimpleImmutableEntry<Filter,String> entry = processFilter(null, null);
        if (entry == null) {
            return null;
        } else {
            return entry.getKey();
        }
    }
    
    public final String getDynamicMask() {
        String ip = getIP();
        String helo = getHELO();
        String mask = Generic.findDynamic(helo);
        if (mask == null) {
            mask = Generic.getDynamicMaskRDNS(ip);
        }
        return mask;
    }

    public final String getFlow() {
        StringBuilder builder = new StringBuilder();
        String userEmail = getUserEmail();
        builder.append(userEmail);
        builder.append(':');
        String sender = getTrueSender();
        String fqdn = getFQDN();
        String helo = getHELO();
        if (sender != null) {
            builder.append(sender);
        } else if (fqdn != null) {
            builder.append(fqdn);
        } else {
            builder.append(helo);
        }
        String messageID = getMessageID();
        if (messageID != null) {
            builder.append(';');
            builder.append(messageID);
        }
        TreeSet<String> recipientSet = getRecipientSet();
        if (recipientSet != null && recipientSet.size() == 1) {
            String recipient = recipientSet.first();
            builder.append('>');
            builder.append(recipient);
        }
        return builder.toString();
    }

    public final SimpleImmutableEntry<Filter,String> processFilter(
            Client client, Filter previous
    ) {
        String ip = getIP();
        String fqdn = getFQDN();
        String sender = getSender();
        Qualifier qualifier = getQualifier();
        String from = getFrom();
        Flag spfFlag;
        Flag dkimFlag;
        Flag fqdnFlag;
        Flag cidrFlag;
        Flag subjectFlag;
        Flag abuseFlag;
        Flag recipientFlag;
        Flag envelopeFlag;
        int usingSince = usingSince();
        String resultLocal;
        // Static section.
        if (hasMalwareNotIgnored()) {
            return new SimpleImmutableEntry(Filter.MALWARE_NOT_IGNORED, getMalware()); // 99,98%
        } else if (isWhiteKey()) {
            return new SimpleImmutableEntry(Filter.ORIGIN_WHITE_KEY_USER, null); // 50,00%
        } else if (isBanned()) {
            return new SimpleImmutableEntry(Filter.ORIGIN_BANNED, getBannedKey()); // 50,00%
        } else if (isBlockKey()) {
            return new SimpleImmutableEntry(Filter.ORIGIN_BLOCK_KEY_USER, null); // 50,00%
        } else if (isRecipientAbuse()) {
            return new SimpleImmutableEntry(Filter.RECIPIENT_ABUSE, getUserEmail() + ':' + getRecipientFirst()); // 95,72%
        } else if (isRecipientPrivate()) {
            return new SimpleImmutableEntry(Filter.RECIPIENT_PRIVATE, getUserEmail() + ':' + getRecipientFirst()); // 98,80%
        } else if (isSenderMailerDeamon() && isRecipientHacked()) {
            return new SimpleImmutableEntry(Filter.RECIPIENT_HACKED, getUserEmail() + ':' + getRecipientFirst()); // 50,00%
        // Dynamic section.
        } else if (inReplyToContainsRecipient() && isDesirable()) {
            return new SimpleImmutableEntry(Filter.IN_REPLY_TO_DESIRABLE, null); // 100,00%
        } else if ((recipientFlag = getRecipientFlag()) == UNDESIRABLE && usingSince < 7 && isUndesirable()) {
            return new SimpleImmutableEntry(Filter.RECIPIENT_UNDESIRABLE, null); // 99,96%
        } else if (isAbuseBlocked(usingSince, qualifier, spfFlag = getFlagSPF(sender, qualifier), fqdn, previous)) {
            return new SimpleImmutableEntry(Filter.ABUSE_BLOCKED, getUserEmail() + ':' + getAbuseOrigin()); // 99,95%
        } else if ((abuseFlag = getFlagAbuse()) == HARMFUL) {
            return new SimpleImmutableEntry(Filter.ABUSE_HARMFUL, getAbuseOrigin()); // 99,94%
        } else if (sender == null && sentByBULK()) {
            return new SimpleImmutableEntry(Filter.BULK_BOUNCE, null); // 99,91%
        } else if ((envelopeFlag = getFlagEnvelope()) == BENEFICIAL) {
            return new SimpleImmutableEntry(Filter.ENVELOPE_BENEFICIAL, null); // 99,90%
        } else if ((resultLocal = getSpoofingFrom()) != null) {
            return new SimpleImmutableEntry(Filter.FROM_SPOOFED_SENDER, resultLocal); // 99,88%
        } else if ((resultLocal = getWhiteReason()) != null) {
            return new SimpleImmutableEntry(Filter.ORIGIN_WHITELISTED, null); // 99,88%
        } else if (usingSince > 7 && isSenderMailerDeamon()) {
            return new SimpleImmutableEntry(Filter.SENDER_MAILER_DEAMON, null); // 99,87%
        } else if ((subjectFlag = getSubjectFlag()) == UNDESIRABLE) {
            return new SimpleImmutableEntry(Filter.SUBJECT_UNDESIRABLE, getSubjectFlagCause()); // 99,82%
        } else if ((dkimFlag = getFlagDKIM(from, getSignerSet())) == BENEFICIAL && usingSince > 7) {
            return new SimpleImmutableEntry(Filter.DKIM_BENEFICIAL, null); // 99,82%
        } else if (sender != null && subjectFlag == BENEFICIAL && usingSince > 7 && SPF.isGreen(simplifyEmail(sender))) {
            return new SimpleImmutableEntry(Filter.SUBJECT_BENEFICIAL, getSubjectFlagCause()); // 99,74%
        } else if (subjectFlag == HARMFUL) {
            return new SimpleImmutableEntry(Filter.SUBJECT_HARMFUL, getSubjectFlagCause()); // 99,71%
        } else if (inReplyToContainsRecipient() && !isDesirable()) {
            return new SimpleImmutableEntry(Filter.IN_REPLY_TO_EXISTENT, null); // 99,71%
        } else if ((resultLocal = getAnyLinkSuspect(false)) != null && isUndesirable()) {
            return new SimpleImmutableEntry(Filter.HREF_UNDESIRABLE, resultLocal); // 99,69%
        } else if ((resultLocal = getFromBlocked()) != null) {
            return new SimpleImmutableEntry(Filter.FROM_BLOCKED, resultLocal); // 99,69%
        } else if (isWhiteKeyByAdmin()) {
            return new SimpleImmutableEntry(Filter.ORIGIN_WHITE_KEY_ADMIN, null); // 99,68%
        } else if (recipientFlag == BENEFICIAL && usingSince > 7  && isDesirable()) {
            return new SimpleImmutableEntry(Filter.RECIPIENT_BENEFICIAL, null); // 99,68%
        } else if ((cidrFlag = getFlagCIDR(ip)) == BENEFICIAL && !sentByBULK()) {
            return new SimpleImmutableEntry(Filter.CIDR_BENEFICIAL, null); // 99,67%
        } else if (spfFlag == DESIRABLE && usingSince > 7) {
            return new SimpleImmutableEntry(Filter.SPF_DESIRABLE, null); // 99,65%
        } else if (isTrustedMailerDaemon()) {
            return new SimpleImmutableEntry(Filter.SENDER_MAILER_DEAMON_TRUSTED, simplifyEmail(from)); // 99,64%
        } else if (abuseFlag == BENEFICIAL) {
            return new SimpleImmutableEntry(Filter.ABUSE_BENEFICIAL, getAbuseOrigin()); // 99,64%
        } else if (hasExecutableNotIgnored() && isUndesirable()) {
            return new SimpleImmutableEntry(Filter.EXECUTABLE_UNDESIRABLE, null); // 99,60%
        } else if ((fqdnFlag = getFlagFQDN()) == BENEFICIAL) {
            return new SimpleImmutableEntry(Filter.FQDN_BENEFICIAL, fqdn); // 99,58%
        } else if (recipientFlag == DESIRABLE && usingSince > 7 && isDesirable()) {
            return new SimpleImmutableEntry(Filter.RECIPIENT_DESIRABLE, null); // 99,55%
        } else if (spfFlag == BENEFICIAL && usingSince > 7) {
            return new SimpleImmutableEntry(Filter.SPF_BENEFICIAL, simplifyEmail(sender)); // 99,53%
        } else if (recipientFlag == HARMFUL && isUndesirable()) {
            return new SimpleImmutableEntry(Filter.RECIPIENT_HARMFUL, null); // 99,40%
        } else if (isForgedFrom()) {
            return new SimpleImmutableEntry(Filter.FROM_FORGED, null); // 99,40%
        } else if (isBlockKeyByAdmin()) {
            return new SimpleImmutableEntry(Filter.ORIGIN_BLOCK_KEY_ADMIN, getBlockKey()); // 99,38%
        } else if (fqdnFlag == DESIRABLE && (cidrFlag == DESIRABLE || cidrFlag == BENEFICIAL)) {
            return new SimpleImmutableEntry(Filter.FQDN_DESIRABLE, fqdn); // 99,38%
        } else if (isFromUnroutable()) {
            return new SimpleImmutableEntry(Filter.FROM_UNROUTABLE, simplifyEmail(getFrom())); // 99,21%
        } else if (isSpoofedRecipient()) {
            return new SimpleImmutableEntry(Filter.FROM_SPOOFED_RECIPIENT, null); // 99,13%
        } else if (dkimFlag == HARMFUL) {
            return new SimpleImmutableEntry(Filter.DKIM_HARMFUL, simplifyEmail(from)); // 98,84%
        } else if (!isPass() && !isEnvelopeFreeMail() && sentByBULK() && Reputation.isBeneficial(ip, fqdn)) {
            return new SimpleImmutableEntry(Filter.BULK_BENEFICIAL, null); // 98,41%
        } else if (!isPass() && !hasFQDN() && !isBounceMessage() && isFromNotSigned() && !isSenderMailerDeamon()) {
            return new SimpleImmutableEntry(Filter.FROM_NOT_SIGNED, null); // 98,25%
        } else if (hasExecutableBlocked()) {
            return new SimpleImmutableEntry(Filter.EXECUTABLE_BLOCKED, null); // 97,96%
        } else if ((resultLocal = getPhishingBlocked()) != null) {
            return new SimpleImmutableEntry(Filter.PHISHING_BLOCKED, resultLocal); // 97,73%
        } else if (sender == null && from == null && !sentByBULK()) {
            return new SimpleImmutableEntry(Filter.FROM_ABSENT, Domain.extractDomainSafe(fqdn, false)); // 97,00%
        } else if (usingSince == -1) {
            return new SimpleImmutableEntry(Filter.DOMAIN_INEXISTENT, null); // 96,97%
        } else if (previous == Filter.FQDN_PROVIDER && usingSince > 7 && SPF.isGreen('.' + fqdn)) {
            return new SimpleImmutableEntry(Filter.FQDN_PROVIDER, null); // 96,65%
        } else if (isToPostmaster()) {
            return new SimpleImmutableEntry(Filter.RECIPIENT_POSTMASTER, null); // 96,40%
        } else if ((resultLocal = getDynamicMask()) != null) {
            return new SimpleImmutableEntry(Filter.IP_DYNAMIC, resultLocal); // 95,96%
        } else if (dkimFlag == DESIRABLE && usingSince > 7) {
            return new SimpleImmutableEntry(Filter.DKIM_DESIRABLE, simplifyEmail(from)); // 95,58%
        } else if (sender != null && subjectFlag == DESIRABLE && usingSince > 7 && SPF.isGreen(simplifyEmail(sender))) {
            return new SimpleImmutableEntry(Filter.SUBJECT_DESIRABLE, getSubjectFlagCause()); // 91,89%
        } else if (isSigned(sender) && Ignore.contains(sender) && SPF.isGreen(simplifyEmail(sender))) {
            return new SimpleImmutableEntry(Filter.SENDER_ESSENTIAL, simplifyEmail(sender)); // 90,75%
        } else if (isSpoofingFQDN()) {
            return new SimpleImmutableEntry(Filter.FQDN_SPOOFED, null); // 87,50%
        } else if (from != null && from.contains(getRecipientHostname(false)) && isNotSigned(from)) {
            return new SimpleImmutableEntry(Filter.RECIPIENT_SPOOFING, null); // 85,71%
        } else if (spfFlag == HARMFUL) {
            return new SimpleImmutableEntry(Filter.SPF_HARMFUL, simplifyEmail(sender)); // 83,24%
        } else if (previous == Filter.ENVELOPE_BLOCKED) {
            return new SimpleImmutableEntry(Filter.ENVELOPE_BLOCKED, null); // 82,95%
        } else if ((resultLocal = getBlock()) != null) {
            return new SimpleImmutableEntry(Filter.ORIGIN_BLOCKED, resultLocal); // 78,70%
        } else if (fqdn != null && !sentByBULK() && SPF.isRed('.' + fqdn)) {
            return new SimpleImmutableEntry(Filter.FQDN_RED, '.' + fqdn); // 77,48%
        } else if ((resultLocal = getSpoofingSender()) != null) {
            return new SimpleImmutableEntry(Filter.SENDER_SPOOFING, resultLocal); // 75,00%
        } else if (!isPass() && getFQDN() == null && !isHostname(getHELO())) {
            return new SimpleImmutableEntry(Filter.HELO_ANONYMOUS, null); // 75,00%
        } else if (hasExecutableNotIgnored() && !isUndesirable()) {
            return new SimpleImmutableEntry(Filter.EXECUTABLE_NOT_IGNORED, null); // 67,79%
        } else if (spfFlag == UNDESIRABLE && !Provider.containsDomain(sender)) {
            return new SimpleImmutableEntry(Filter.SPF_UNDESIRABLE, simplifyEmail(sender)); // 66,64%
        } else if (isRecipientRestrict()) {
            return new SimpleImmutableEntry(Filter.RECIPIENT_RESTRICT, getUserEmail() + ':' + getRecipientFirst()); // 66,34%
        } else if (isPass() && SPF.isRed(simplifyEmail(sender)) && !Provider.containsDomain(sender)) {
            return new SimpleImmutableEntry(Filter.SENDER_RED, simplifyEmail(sender)); // 65,23%
        } else if (previous == Filter.ENVELOPE_INVALID) {
            return new SimpleImmutableEntry(Filter.ENVELOPE_INVALID, null); // 63,14%
        } else if (isPass() && Ignore.containsFQDN(fqdn) && SPF.isGreen('.' + fqdn)) {
            return new SimpleImmutableEntry(Filter.FQDN_ESSENTIAL, fqdn); // 60,59%
        } else if (Provider.isFreeMail(from) && !Provider.containsFQDN(fqdn) && !isSigned(from)) {
            return new SimpleImmutableEntry(Filter.FROM_FREEMAIL, null); // 58,82%
        } else if (fqdnFlag == UNDESIRABLE && (cidrFlag == UNDESIRABLE || cidrFlag == HARMFUL)) {
            return new SimpleImmutableEntry(Filter.FQDN_UNDESIRABLE, fqdn); // 57,38%
        } else if (qualifier == FAIL && isFromNotSigned()) {
            return new SimpleImmutableEntry(Filter.SPF_FAIL, null); // 51,29%
        } else if (envelopeFlag == HARMFUL) {
            return new SimpleImmutableEntry(Filter.ENVELOPE_HARMFUL, null); // 50,0%
        } else if (envelopeFlag == DESIRABLE) {
            return new SimpleImmutableEntry(Filter.ENVELOPE_DESIRABLE, null); // 50,0%
        } else if (previous == Filter.ORIGIN_UNDESIRABLE) {
            return new SimpleImmutableEntry(Filter.ORIGIN_UNDESIRABLE, null); // 50,00%
        } else if (previous == Filter.ORIGIN_HARMFUL) {
            return new SimpleImmutableEntry(Filter.ORIGIN_HARMFUL, null); // 50,00%
        } else if (isNotSigned(sender) && isFromNXDOMAIN()) {
            return new SimpleImmutableEntry(Filter.FROM_NXDOMAIN, null); // 50,00%
        } else if (dkimFlag == UNDESIRABLE) {
            return new SimpleImmutableEntry(Filter.DKIM_UNDESIRABLE, simplifyEmail(from)); // 50,00%
        } else if (cidrFlag == HARMFUL && (resultLocal = Block.findCIDR(getIP())) != null) {
            return new SimpleImmutableEntry(Filter.CIDR_HARMFUL, resultLocal); // 50,00%
        } else if (fqdnFlag == HARMFUL && cidrFlag == HARMFUL) {
            return new SimpleImmutableEntry(Filter.FQDN_HARMFUL, fqdn); // 50,00%
        } else if (isNotSigned(from) && isSenderNXDOMAIN()) {
            return new SimpleImmutableEntry(Filter.SENDER_NXDOMAIN, null); // 50,00%
        } else if (sender != null && qualifier == null && !Domain.isMailFrom(sender)) {
            return new SimpleImmutableEntry(Filter.SENDER_INVALID, sender); // 50,00%
        } else if (previous == Filter.SPF_NXDOMAIN) {
            return new SimpleImmutableEntry(Filter.SPF_NXDOMAIN, null); // 50,00%
        } else if (qualifier == FAIL && fqdn == null) {
            return new SimpleImmutableEntry(Filter.SPF_SPOOFING, null); // 50,00%
        } else if (envelopeFlag == UNDESIRABLE) {
            return new SimpleImmutableEntry(Filter.ENVELOPE_UNDESIRABLE, null); // 50,00%
        } else if ((resultLocal = getAnyLinkSuspect(false)) != null) {
            return new SimpleImmutableEntry(Filter.HREF_SUSPECT, resultLocal); // 47,96%
        } else if (qualifier == SOFTFAIL && isFromNotSigned() && !sentByBULK()) {
            return new SimpleImmutableEntry(Filter.SPF_SOFTFAIL, null); // 35,38%
        } else if (isSigned(from) && Ignore.contains(from)) {
            return new SimpleImmutableEntry(Filter.FROM_ESSENTIAL, simplifyEmail(from)); // 20,09%
        } else if (usingSince < 7 && !sentByBULK()) {
            return new SimpleImmutableEntry(Filter.DOMAIN_EMERGED, Integer.toString(usingSince)); // 26,63%
        } else if (hasSuspectFrom()) {
            return new SimpleImmutableEntry(Filter.FROM_SUSPECT, null); // 34,73%
        } else {
            return null;
        }
    }
    
    public final SimpleImmutableEntry<Filter,String> processFilterExpired() {
        String reason;
        if (isBlockKeyByAdmin()) {
            return new SimpleImmutableEntry(Filter.HOLD_BLOCK_KEY_ADMIN, getBlockKey()); // 99,93%
        } else if ((reason = getBlock()) != null) {
            return new SimpleImmutableEntry(Filter.HOLD_BLOCKED, reason); // 98,60%
        } else if (isWhiteKeyByAdmin()) {
            return new SimpleImmutableEntry(Filter.HOLD_WHITE_KEY_ADMIN, getBlockKey()); // 97,64%
        } else if ((reason = getWhiteReason()) != null) {
            return new SimpleImmutableEntry(Filter.HOLD_WHITELISTED, reason); // 97,14%
        } else if (isPass() && SPF.isRed(simplifyEmail(getSender()))) {
            return new SimpleImmutableEntry(Filter.HOLD_SENDER_RED, null); // 96,97%
        } else if (isUndesirable()) {
            return new SimpleImmutableEntry(Filter.HOLD_UNDESIRABLE, null); // 93,81%
        } else if (isFilter(Filter.RECIPIENT_RESTRICT)) {
            return new SimpleImmutableEntry(Filter.HOLD_RECIPIENT_RESTRICT, null); // 92,86%
        } else if (isFilter(Filter.DOMAIN_EMERGED)) {
            return new SimpleImmutableEntry(Filter.HOLD_DOMAIN_EMERGED, null); // 89,15%
        } else if (isFilter(Filter.ENVELOPE_BLOCKED)) {
            return new SimpleImmutableEntry(Filter.HOLD_ENVELOPE_BLOCKED, null); // 89,07%
        } else if ((reason = getAnyLinkSuspect(false)) != null) {
            return new SimpleImmutableEntry(Filter.HOLD_HREF_SUSPECT, reason); // 86,84%
        } else if (isSoftfail()) {
            return new SimpleImmutableEntry(Filter.HOLD_SPF_SOFTFAIL, null); // 76,00%
        } else if (hasFQDN() && SPF.isRed('.' + getFQDN())) {
            return new SimpleImmutableEntry(Filter.HOLD_FQDN_RED, null); // 66,67%
        } else if (isFail()) {
            return new SimpleImmutableEntry(Filter.HOLD_SPF_FAIL, null); // 50,00%
        } else if (isWhiteKey()) {
            return new SimpleImmutableEntry(Filter.HOLD_WHITE_KEY_USER, null); // 50,00%
        } else if (isBanned()) {
            return new SimpleImmutableEntry(Filter.HOLD_BANNED, getBannedKey()); // 50,00%
        } else if (isBlockKey()) {
            return new SimpleImmutableEntry(Filter.HOLD_BLOCK_KEY_USER, null); // 50,00%
        } else if (isFilter(Filter.RECIPIENT_UNDESIRABLE)) {
            return new SimpleImmutableEntry(Filter.HOLD_RECIPIENT_UNDESIRABLE, null); // 50,00%
        } else if (isFilter(Filter.ENVELOPE_UNDESIRABLE)) {
            return new SimpleImmutableEntry(Filter.HOLD_ENVELOPE_UNDESIRABLE, null); // 50,00%
        } else {
            return new SimpleImmutableEntry(Filter.HOLD_EXPIRED, null); // 79,64%
        }
    }
}
