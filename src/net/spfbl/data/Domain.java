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
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Objects;
import java.util.StringTokenizer;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import java.util.regex.Matcher;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import net.spfbl.core.Core;
import net.spfbl.core.Regex;
import static net.spfbl.core.Regex.isHostname;
import static net.spfbl.core.Regex.isValidIPv4;
import static net.spfbl.core.Regex.isValidIPv6;
import net.spfbl.core.Server;

/**
 * Represents the information structure of the root domain.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Domain {
    
    private static long FIRST = Long.MAX_VALUE;
    
    private final long first;
    private final boolean active;
    private int last;
    private String owner;
    
    private Domain(boolean active) {
        this.first = System.currentTimeMillis();
        this.active = active;
        this.last = TIME;
        this.owner = null;
        if (FIRST > first) {
            FIRST = first;
        }
    }
    
    private Domain(StringTokenizer tokenizer) {
        this.first = Long.parseLong(tokenizer.nextToken());
        this.active = Boolean.parseBoolean(tokenizer.nextToken());
        this.last = Integer.parseInt(tokenizer.nextToken());
        if (tokenizer.hasMoreTokens()) {
            this.owner = tokenizer.nextToken();
        }
        if (FIRST > first) {
            FIRST = first;
        }
    }
    
    public boolean equals(Domain other) {
        if (other == null) {
            return false;
        } else if (this.first != other.first) {
            return false;
        } else if (this.active != other.active) {
            return false;
        } else if (this.last != other.last) {
            return false;
        } else {
            return Objects.equals(this.owner, other.owner);
        }
    }
    
    public boolean isActive() {
        last = TIME;
        return active;
    }
    
    public Integer usingSince() {
        last = TIME;
        if (!active) {
            return null;
        } else if (((System.currentTimeMillis() - FIRST) / Server.DAY_TIME) < 90) {
            return Integer.MAX_VALUE;
        } else {
            return (int) ((System.currentTimeMillis() - first) / Server.DAY_TIME);
        }
    }
    
    private boolean isExpired() {
        if (active) {
            return TIME - last > 3;
        } else {
            return (int) ((System.currentTimeMillis() - first) / Server.DAY_TIME) > 7;
        }
    }
    
    private String getLine() {
        if (owner == null) {
            return first + " " + active + " " + last;
        } else {
            return first + " " + active + " " + last + " " + owner;
        }
    }
    
    /**
     * General map of root domains.
     */
    private static final HashMap<String,Domain> MAP = new HashMap<>();
    
    private synchronized static boolean put(String name, Domain domain) {
        if (name == null) {
            return false;
        } else if (domain == null) {
            return false;
        } else if (domain.equals(MAP.put(name, domain))) {
            return false;
        } else {
            return true;
        }
    }
    
    private static boolean add(String name, Domain domain) {
        if (put(name, domain)) {
            append("PUT " + name + " " + domain.getLine());
            return true;
        } else {
            return false;
        }
    }
    
    private synchronized static TreeSet<String> keySet() {
        TreeSet<String> keySet = new TreeSet<>();
        keySet.addAll(MAP.keySet());
        return keySet;
    }
    
    private synchronized static Domain remove(String name) {
        if (name == null) {
            return null;
        } else {
            return MAP.remove(name);
        }
    }
    
    private static Domain drop(String name) {
        Domain domain = remove(name);
        if (domain == null) {
            return null;
        } else {
            append("DROP " + name);
            return domain;
        }
    }
    
    private static Domain get(String name) {
        if (name == null) {
            return null;
        } else {
            return MAP.get(name);
        }
    }
    
    public static Domain getDomain(String name) {
        if (Provider.isFreeMail(name)) {
            if ((name = net.spfbl.whois.Domain.normalizeEmail(name)) == null) {
                return null;
            } else {
                return get(name);
            }
        } else {
            if ((name = extractRootDomain(name)) == null) {
                return null;
            } else {
                return get(name);
            }
        }
    }
    
    private static Domain newDomain(String name) {
        if (name == null) {
            return null;
        } else {
            Domain domain = get(name);
            if (domain == null) {
                boolean active = isActive(name);
                domain = new Domain(active);
                add(name, domain);
            }
            return domain;
        }
    }
    
    public static boolean isInexistent(String name) {
        if (name == null) {
            return false;
        } else if (name.contains("@")) {
            // TODO: existent verification
            return true;
        } else {
            Domain domain = newDomain(name);
            if (domain == null) {
                return false;
            } else {
                return !domain.isActive();
            }
        }
    }
    
    private static boolean isActive(String name) {
        if (name == null) {
            return false;
        } else if (name.contains("@")) {
            // TODO: existent verification
            return true;
        } else {
            try {
                try {
                    Attributes attributesNS = Server.getAttributesDNS(name, "NS");
                    if (attributesNS != null) {
                        Enumeration enumerationNS = attributesNS.getAll();
                        while (enumerationNS.hasMoreElements()) {
                            Attribute attributeNS = (Attribute) enumerationNS.nextElement();
                            NamingEnumeration enumeration = attributeNS.getAll();
                            while (enumeration.hasMoreElements()) {
                                String ns = (String) enumeration.next();
                                if (isHostname(ns)) {
                                    return true;
                                }
                            }
                        }
                    }
                } catch (NamingException ex) {
                    // Do nothing.
                }
                try {
                    Attributes attributesAAAA = Server.getAttributesDNS(name, "AAAA");
                    if (attributesAAAA != null) {
                        Enumeration enumerationAAAA = attributesAAAA.getAll();
                        while (enumerationAAAA.hasMoreElements()) {
                            Attribute attributeAAAA = (Attribute) enumerationAAAA.nextElement();
                            NamingEnumeration enumeration = attributeAAAA.getAll();
                            while (enumeration.hasMoreElements()) {
                                String address = (String) enumeration.next();
                                if (isValidIPv6(address)) {
                                    return true;
                                }
                            }
                        }
                    }
                } catch (NamingException ex) {
                    // Do nothing.
                }
                try {
                    Attributes attributesA = Server.getAttributesDNS(name, "A");
                    if (attributesA != null) {
                        Enumeration enumerationA = attributesA.getAll();
                        while (enumerationA.hasMoreElements()) {
                            Attribute attributeA = (Attribute) enumerationA.nextElement();
                            NamingEnumeration enumeration = attributeA.getAll();
                            while (enumeration.hasMoreElements()) {
                                String address = (String) enumeration.next();
                                if (isValidIPv4(address)) {
                                    return true;
                                }
                            }
                        }
                    }
                } catch (NamingException ex) {
                    // Do nothing.
                }
                try {
                    Attributes attributes = Server.getAttributesDNS(name, "MX");
                    if (attributes != null) {
                        Enumeration enumerationTXT = attributes.getAll();
                        while (enumerationTXT.hasMoreElements()) {
                            Attribute attributeTXT = (Attribute) enumerationTXT.nextElement();
                            NamingEnumeration enumeration = attributeTXT.getAll();
                            while (enumeration.hasMoreElements()) {
                                String mx = (String) enumeration.next();
                                int index = mx.indexOf(' ');
                                if (index > 0) {
                                    String priority = mx.substring(0, index);
                                    if (Core.isInteger(priority)) {
                                        String fqdn = mx.substring(index + 1);
                                        if (isHostname(fqdn)) {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                } catch (NamingException ex) {
                    // Do nothing.
                }
                return false;
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        }
    }
    
    public static String extractRootDomain(String... list) {
        if (list == null) {
            return null;
        } else {
            TreeSet<String> resultSet = new TreeSet<>();
            for (String name : list) {
                if (Provider.isFreeMail(name)) {
                    String email = net.spfbl.whois.Domain.normalizeEmail(name);
                    if (email != null) {
                        resultSet.add(email);
                    }
                } else {
                    String domain = extractRootDomain(name);
                    if (domain != null) {
                        resultSet.add(domain);
                    }
                }
            }
            return resultSet.toString().replace(" ", "");
        }
    }
    
    private static final Regex PATTERN = new Regex("^"
            + "([a-z0-9._%+=-]+@|\\.)?"
            + "(([a-z0-9_]|[a-z0-9_][a-z0-9_-]{0,61}[a-z0-9])"
            + "(\\.([a-z0-9_]|[a-z0-9_][a-z0-9_-]{0,61}[a-z0-9]))*)"
            + "\\.?$"
    );
    
    public static boolean isRootDomain(String name) {
        if (name == null) {
            return false;
        } else if (net.spfbl.whois.Domain.containsTLD('.' + name)) {
            return false;
        } else {
            int index = name.indexOf('.') + 1;
            name = '.' + name.substring(index);
            return net.spfbl.whois.Domain.containsTLD(name);
        }
    }
    
    public static String extractRootDomain(String name) {
        if (name == null) {
            return null;
        } else {
            try {
                Matcher matcher = PATTERN.createMatcher(name.toLowerCase());
                if (matcher.find()) {
                    name = '.' + matcher.group(2);
                    PATTERN.offerMatcher(matcher);
                    int index = name.lastIndexOf('.');
                    String domain = name.substring(index);
                    while (net.spfbl.whois.Domain.containsTLD(domain)) {
                        index = name.lastIndexOf('.', index - 1);
                        if (index == -1) {
                            return null;
                        } else {
                            domain = name.substring(index);
                        }
                    }
                    domain = domain.substring(1);
                    if (domain.matches("[0-9]+")) {
                        return null;
                    } else {
                        return domain;
                    }
                } else {
                    PATTERN.offerMatcher(matcher);
                    return null;
                }
                
            } catch (Exception ex) {
                Server.logError(ex);
                return null;
            }
        }
    }
    
    public static int usingSinceInt(String name) {
        Integer since = usingSince(name);
        if (since == null) {
            return -1;
        } else {
            return since;
        }
    }
    
    public static Integer usingSince(String name) {
        if (Provider.isFreeMail(name)) {
            if ((name = net.spfbl.whois.Domain.normalizeEmail(name)) == null) {
                return null;
            } else {
                Domain domain = newDomain(name);
                return domain.usingSince();
            }
        } else {
            if ((name = extractRootDomain(name)) == null) {
                return null;
            } else {
                Domain domain = newDomain(name);
                return domain.usingSince();
            }
        }
    }
    
    public static Integer usingSinceNewest(String... list) {
        if (list == null) {
            return null;
        } else {
            Integer result = null;
            for (String name : list) {
                Integer since = usingSince(name);
                if (since != null) {
                    if (result == null) {
                        result = since;
                    } else if (result > since) {
                        result = since;
                    }
                }
            }
            return result;
        }
    }
    
    private static int TIME = (int) (System.currentTimeMillis() >>> 32);

    private static void refreshTime() {
        TIME = (int) (System.currentTimeMillis() >>> 32);
    }
    
    private static final File FILE = new File("./data/domain.txt");
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
                        StringTokenizer tokenizer = new StringTokenizer(line, " ");
                        String token = tokenizer.nextToken();
                        if (token.equals("PUT") && tokenizer.countTokens() == 4) {
                            String name = tokenizer.nextToken();
                            Domain domain = new Domain(tokenizer);
                            put(name, domain);
                        } else if (token.equals("DROP")) {
                            String name = tokenizer.nextToken();
                            remove(name);
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
        refreshTime();
        try {
            long time = System.currentTimeMillis();
            SEMAPHORE.acquire();
            try {
                WRITER.close();
                Path source = FILE.toPath();
                Path temp = source.resolveSibling('.' + FILE.getName());
                try (FileWriter writer = new FileWriter(temp.toFile())) {
                    for (String name : keySet()) {
                        Domain domain = get(name);
                        if (domain == null) {
                            remove(name);
                        } else if (domain.isExpired()) {
                            remove(name);
                        } else if (isRootDomain(name)) {
                            writer.write("PUT ");
                            writer.write(name);
                            writer.write(' ');
                            writer.write(domain.getLine());
                            writer.write('\n');
                            writer.flush();
                        } else {
                            remove(name);
                        }
                    }
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
    
    private static String getWhoisServer(String name) {
        if (name == null) {
            return null;
        } else if (name.endsWith(".ac")) {
            return "whois.nic.ac";
        } else if (name.endsWith(".ad")) {
            return "whois.ripe.net";
        } else if (name.endsWith(".ae")) {
            return "whois.aeda.net.ae";
        } else if (name.endsWith(".aero")) {
            return "whois.aero";
        } else if (name.endsWith(".af")) {
            return "whois.nic.af";
        } else if (name.endsWith(".ag")) {
            return "whois.nic.ag";
        } else if (name.endsWith(".ai")) {
            return "whois.ai";
        } else if (name.endsWith(".al")) {
            return "whois.ripe.net";
        } else if (name.endsWith(".am")) {
            return "whois.amnic.net";
        } else if (name.endsWith(".as")) {
            return "whois.nic.as";
        } else if (name.endsWith(".asia")) {
            return "whois.nic.asia";
        } else if (name.endsWith(".at")) {
            return "whois.nic.at";
        } else if (name.endsWith(".au")) {
            return "whois.aunic.net";
        } else if (name.endsWith(".aw")) {
            return "whois.nic.aw";
        } else if (name.endsWith(".ax")) {
            return "whois.ax";
        } else if (name.endsWith(".az")) {
            return "whois.ripe.net";
        } else if (name.endsWith(".ba")) {
            return "whois.ripe.net";
        } else if (name.endsWith(".bar")) {
            return "whois.nic.bar";
        } else if (name.endsWith(".be")) {
            return "whois.dns.be";
        } else if (name.endsWith(".berlin")) {
            return "whois.nic.berlin";
        } else if (name.endsWith(".best")) {
            return "whois.nic.best";
        } else if (name.endsWith(".bg")) {
            return "whois.register.bg";
        } else if (name.endsWith(".bi")) {
            return "whois.nic.bi";
        } else if (name.endsWith(".biz")) {
            return "whois.neulevel.biz";
        } else if (name.endsWith(".bj")) {
            return "www.nic.bj";
        } else if (name.endsWith(".bo")) {
            return "whois.nic.bo";
        } else if (name.endsWith(".br")) {
            return "whois.nic.br";
        } else if (name.endsWith(".br.com")) {
            return "whois.centralnic.com";
        } else if (name.endsWith(".bt")) {
            return "whois.netnames.net";
        } else if (name.endsWith(".bw")) {
            return "whois.nic.net.bw";
        } else if (name.endsWith(".by")) {
            return "whois.cctld.by";
        } else if (name.endsWith(".bz")) {
            return "whois.belizenic.bz";
        } else if (name.endsWith(".bzh")) {
            return "whois-bzh.nic.fr";
        } else if (name.endsWith(".ca")) {
            return "whois.cira.ca";
        } else if (name.endsWith(".cat")) {
            return "whois.cat";
        } else if (name.endsWith(".cc")) {
            return "whois.nic.cc";
        } else if (name.endsWith(".cd")) {
            return "whois.nic.cd";
        } else if (name.endsWith(".ceo")) {
            return "whois.nic.ceo";
        } else if (name.endsWith(".cf")) {
            return "whois.dot.cf";
        } else if (name.endsWith(".ch")) {
            return "whois.nic.ch";
        } else if (name.endsWith(".ci")) {
            return "whois.nic.ci";
        } else if (name.endsWith(".ck")) {
            return "whois.nic.ck";
        } else if (name.endsWith(".cl")) {
            return "whois.nic.cl";
        } else if (name.endsWith(".cloud")) {
            return "whois.nic.cloud";
        } else if (name.endsWith(".club")) {
            return "whois.nic.club";
        } else if (name.endsWith(".cn")) {
            return "whois.cnnic.net.cn";
        } else if (name.endsWith(".cn.com")) {
            return "whois.centralnic.com";
        } else if (name.endsWith(".co")) {
            return "whois.nic.co";
        } else if (name.endsWith(".co.nl")) {
            return "whois.co.nl";
        } else if (name.endsWith(".com")) {
            return "whois.verisign-grs.com";
        } else if (name.endsWith(".coop")) {
            return "whois.nic.coop";
        } else if (name.endsWith(".cx")) {
            return "whois.nic.cx";
        } else if (name.endsWith(".cy")) {
            return "whois.ripe.net";
        } else if (name.endsWith(".cz")) {
            return "whois.nic.cz";
        } else if (name.endsWith(".de")) {
            return "whois.denic.de";
        } else if (name.endsWith(".dk")) {
            return "whois.dk-hostmaster.dk";
        } else if (name.endsWith(".dm")) {
            return "whois.nic.cx";
        } else if (name.endsWith(".dz")) {
            return "whois.nic.dz";
        } else if (name.endsWith(".ec")) {
            return "whois.nic.ec";
        } else if (name.endsWith(".edu")) {
            return "whois.educause.net";
        } else if (name.endsWith(".ee")) {
            return "whois.tld.ee";
        } else if (name.endsWith(".eg")) {
            return "whois.ripe.net";
        } else if (name.endsWith(".es")) {
            return "whois.nic.es";
        } else if (name.endsWith(".eu")) {
            return "whois.eu";
        } else if (name.endsWith(".eu.com")) {
            return "whois.centralnic.com";
        } else if (name.endsWith(".eus")) {
            return "whois.nic.eus";
        } else if (name.endsWith(".fi")) {
            return "whois.fi";
        } else if (name.endsWith(".fo")) {
            return "whois.nic.fo";
        } else if (name.endsWith(".fr")) {
            return "whois.nic.fr";
        } else if (name.endsWith(".gb")) {
            return "whois.ripe.net";
        } else if (name.endsWith(".gb.com")) {
            return "whois.centralnic.com";
        } else if (name.endsWith(".gb.net")) {
            return "whois.centralnic.com";
        } else if (name.endsWith(".qc.com")) {
            return "whois.centralnic.com";
        } else if (name.endsWith(".ge")) {
            return "whois.ripe.net";
        } else if (name.endsWith(".gg")) {
            return "whois.gg";
        } else if (name.endsWith(".gi")) {
            return "whois2.afilias-grs.net";
        } else if (name.endsWith(".gl")) {
            return "whois.nic.gl";
        } else if (name.endsWith(".gm")) {
            return "whois.ripe.net";
        } else if (name.endsWith(".gov")) {
            return "whois.nic.gov";
        } else if (name.endsWith(".gr")) {
            return "whois.ripe.net";
        } else if (name.endsWith(".gs")) {
            return "whois.nic.gs";
        } else if (name.endsWith(".gy")) {
            return "whois.registry.gy";
        } else if (name.endsWith(".hamburg")) {
            return "whois.nic.hamburg";
        } else if (name.endsWith(".hiphop")) {
            return "whois.uniregistry.net";
        } else if (name.endsWith(".hk")) {
            return "whois.hknic.net.hk";
        } else if (name.endsWith(".hm")) {
            return "whois.registry.hm";
        } else if (name.endsWith(".hn")) {
            return "whois2.afilias-grs.net";
        } else if (name.endsWith(".host")) {
            return "whois.nic.host";
        } else if (name.endsWith(".hr")) {
            return "whois.dns.hr";
        } else if (name.endsWith(".ht")) {
            return "whois.nic.ht";
        } else if (name.endsWith(".hu")) {
            return "whois.nic.hu";
        } else if (name.endsWith(".hu.com")) {
            return "whois.centralnic.com";
        } else if (name.endsWith(".id")) {
            return "whois.pandi.or.id";
        } else if (name.endsWith(".ie")) {
            return "whois.domainregistry.ie";
        } else if (name.endsWith(".il")) {
            return "whois.isoc.org.il";
        } else if (name.endsWith(".im")) {
            return "whois.nic.im";
        } else if (name.endsWith(".in")) {
            return "whois.inregistry.net";
        } else if (name.endsWith(".info")) {
            return "whois.afilias.info";
        } else if (name.endsWith(".ing")) {
            return "domain-registry-whois.l.google.com";
        } else if (name.endsWith(".ink")) {
            return "whois.centralnic.com";
        } else if (name.endsWith(".int")) {
            return "whois.isi.edu";
        } else if (name.endsWith(".io")) {
            return "whois.nic.io";
        } else if (name.endsWith(".iq")) {
            return "whois.cmc.iq";
        } else if (name.endsWith(".ir")) {
            return "whois.nic.ir";
        } else if (name.endsWith(".is")) {
            return "whois.isnic.is";
        } else if (name.endsWith(".it")) {
            return "whois.nic.it";
        } else if (name.endsWith(".je")) {
            return "whois.je";
        } else if (name.endsWith(".jobs")) {
            return "jobswhois.verisign-grs.com";
        } else if (name.endsWith(".jp")) {
            return "whois.jprs.jp";
        } else if (name.endsWith(".ke")) {
            return "whois.kenic.or.ke";
        } else if (name.endsWith(".kg")) {
            return "whois.domain.kg";
        } else if (name.endsWith(".ki")) {
            return "whois.nic.ki";
        } else if (name.endsWith(".kr")) {
            return "whois.kr";
        } else if (name.endsWith(".kz")) {
            return "whois.nic.kz";
        } else if (name.endsWith(".la")) {
            return "whois2.afilias-grs.net";
        } else if (name.endsWith(".li")) {
            return "whois.nic.li";
        } else if (name.endsWith(".london")) {
            return "whois.nic.london";
        } else if (name.endsWith(".lt")) {
            return "whois.domreg.lt";
        } else if (name.endsWith(".lu")) {
            return "whois.restena.lu";
        } else if (name.endsWith(".lv")) {
            return "whois.nic.lv";
        } else if (name.endsWith(".ly")) {
            return "whois.lydomains.com";
        } else if (name.endsWith(".ma")) {
            return "whois.iam.net.ma";
        } else if (name.endsWith(".mc")) {
            return "whois.ripe.net";
        } else if (name.endsWith(".md")) {
            return "whois.nic.md";
        } else if (name.endsWith(".me")) {
            return "whois.nic.me";
        } else if (name.endsWith(".mg")) {
            return "whois.nic.mg";
        } else if (name.endsWith(".mil")) {
            return "whois.nic.mil";
        } else if (name.endsWith(".mk")) {
            return "whois.ripe.net";
        } else if (name.endsWith(".ml")) {
            return "whois.dot.ml";
        } else if (name.endsWith(".mo")) {
            return "whois.monic.mo";
        } else if (name.endsWith(".mobi")) {
            return "whois.dotmobiregistry.net";
        } else if (name.endsWith(".ms")) {
            return "whois.nic.ms";
        } else if (name.endsWith(".mt")) {
            return "whois.ripe.net";
        } else if (name.endsWith(".mu")) {
            return "whois.nic.mu";
        } else if (name.endsWith(".museum")) {
            return "whois.museum";
        } else if (name.endsWith(".mx")) {
            return "whois.nic.mx";
        } else if (name.endsWith(".my")) {
            return "whois.mynic.net.my";
        } else if (name.endsWith(".mz")) {
            return "whois.nic.mz";
        } else if (name.endsWith(".na")) {
            return "whois.na-nic.com.na";
        } else if (name.endsWith(".name")) {
            return "whois.nic.name";
        } else if (name.endsWith(".nc")) {
            return "whois.nc";
        } else if (name.endsWith(".net")) {
            return "whois.verisign-grs.com";
        } else if (name.endsWith(".nf")) {
            return "whois.nic.cx";
        } else if (name.endsWith(".ng")) {
            return "whois.nic.net.ng";
        } else if (name.endsWith(".nl")) {
            return "whois.domain-registry.nl";
        } else if (name.endsWith(".no")) {
            return "whois.norid.no";
        } else if (name.endsWith(".no.com")) {
            return "whois.centralnic.com";
        } else if (name.endsWith(".nu")) {
            return "whois.nic.nu";
        } else if (name.endsWith(".nz")) {
            return "whois.srs.net.nz";
        } else if (name.endsWith(".om")) {
            return "whois.registry.om";
        } else if (name.endsWith(".ong")) {
            return "whois.publicinterestregistry.net";
        } else if (name.endsWith(".ooo")) {
            return "whois.nic.ooo";
        } else if (name.endsWith(".org")) {
            return "whois.pir.org";
        } else if (name.endsWith(".paris")) {
            return "whois-paris.nic.fr";
        } else if (name.endsWith(".pe")) {
            return "kero.yachay.pe";
        } else if (name.endsWith(".pf")) {
            return "whois.registry.pf";
        } else if (name.endsWith(".pics")) {
            return "whois.uniregistry.net";
        } else if (name.endsWith(".pl")) {
            return "whois.dns.pl";
        } else if (name.endsWith(".pm")) {
            return "whois.nic.pm";
        } else if (name.endsWith(".pr")) {
            return "whois.nic.pr";
        } else if (name.endsWith(".press")) {
            return "whois.nic.press";
        } else if (name.endsWith(".pro")) {
            return "whois.registrypro.pro";
        } else if (name.endsWith(".pt")) {
            return "whois.dns.pt";
        } else if (name.endsWith(".pub")) {
            return "whois.unitedtld.com";
        } else if (name.endsWith(".pw")) {
            return "whois.nic.pw";
        } else if (name.endsWith(".qa")) {
            return "whois.registry.qa";
        } else if (name.endsWith(".re")) {
            return "whois.nic.re";
        } else if (name.endsWith(".ro")) {
            return "whois.rotld.ro";
        } else if (name.endsWith(".rs")) {
            return "whois.rnids.rs";
        } else if (name.endsWith(".ru")) {
            return "whois.tcinet.ru";
        } else if (name.endsWith(".sa")) {
            return "saudinic.net.sa";
        } else if (name.endsWith(".sa.com")) {
            return "whois.centralnic.com";
        } else if (name.endsWith(".sb")) {
            return "whois.nic.net.sb";
        } else if (name.endsWith(".sc")) {
            return "whois2.afilias-grs.net";
        } else if (name.endsWith(".se")) {
            return "whois.nic-se.se";
        } else if (name.endsWith(".se.com")) {
            return "whois.centralnic.com";
        } else if (name.endsWith(".se.net")) {
            return "whois.centralnic.com";
        } else if (name.endsWith(".sg")) {
            return "whois.nic.net.sg";
        } else if (name.endsWith(".sh")) {
            return "whois.nic.sh";
        } else if (name.endsWith(".si")) {
            return "whois.arnes.si";
        } else if (name.endsWith(".sk")) {
            return "whois.sk-nic.sk";
        } else if (name.endsWith(".sm")) {
            return "whois.nic.sm";
        } else if (name.endsWith(".st")) {
            return "whois.nic.st";
        } else if (name.endsWith(".so")) {
            return "whois.nic.so";
        } else if (name.endsWith(".su")) {
            return "whois.tcinet.ru";
        } else if (name.endsWith(".sx")) {
            return "whois.sx";
        } else if (name.endsWith(".sy")) {
            return "whois.tld.sy";
        } else if (name.endsWith(".tc")) {
            return "whois.adamsnames.tc";
        } else if (name.endsWith(".tel")) {
            return "whois.nic.tel";
        } else if (name.endsWith(".tf")) {
            return "whois.nic.tf";
        } else if (name.endsWith(".th")) {
            return "whois.thnic.net";
        } else if (name.endsWith(".tj")) {
            return "whois.nic.tj";
        } else if (name.endsWith(".tk")) {
            return "whois.nic.tk";
        } else if (name.endsWith(".tl")) {
            return "whois.domains.tl";
        } else if (name.endsWith(".tm")) {
            return "whois.nic.tm";
        } else if (name.endsWith(".tn")) {
            return "whois.ati.tn";
        } else if (name.endsWith(".to")) {
            return "whois.tonic.to";
        } else if (name.endsWith(".top")) {
            return "whois.nic.top";
        } else if (name.endsWith(".tp")) {
            return "whois.domains.tl";
        } else if (name.endsWith(".tr")) {
            return "whois.nic.tr";
        } else if (name.endsWith(".travel")) {
            return "whois.nic.travel";
        } else if (name.endsWith(".tw")) {
            return "whois.twnic.net.tw";
        } else if (name.endsWith(".tv")) {
            return "whois.nic.tv";
        } else if (name.endsWith(".tz")) {
            return "whois.tznic.or.tz";
        } else if (name.endsWith(".ua")) {
            return "whois.ua";
        } else if (name.endsWith(".ug")) {
            return "whois.co.ug";
        } else if (name.endsWith(".uk")) {
            return "whois.nic.uk";
        } else if (name.endsWith(".uk.com")) {
            return "whois.centralnic.com";
        } else if (name.endsWith(".uk.net")) {
            return "whois.centralnic.com";
        } else if (name.endsWith(".ac.uk")) {
            return "whois.ja.net";
        } else if (name.endsWith(".gov.uk")) {
            return "whois.ja.net";
        } else if (name.endsWith(".us")) {
            return "whois.nic.us";
        } else if (name.endsWith(".us.com")) {
            return "whois.centralnic.com";
        } else if (name.endsWith(".uy")) {
            return "nic.uy";
        } else if (name.endsWith(".uy.com")) {
            return "whois.centralnic.com";
        } else if (name.endsWith(".uz")) {
            return "whois.cctld.uz";
        } else if (name.endsWith(".va")) {
            return "whois.ripe.net";
        } else if (name.endsWith(".vc")) {
            return "whois2.afilias-grs.net";
        } else if (name.endsWith(".ve")) {
            return "whois.nic.ve";
        } else if (name.endsWith(".vg")) {
            return "ccwhois.ksregistry.net";
        } else if (name.endsWith(".vu")) {
            return "vunic.vu";
        } else if (name.endsWith(".wang")) {
            return "whois.nic.wang";
        } else if (name.endsWith(".wf")) {
            return "whois.nic.wf";
        } else if (name.endsWith(".wiki")) {
            return "whois.nic.wiki";
        } else if (name.endsWith(".ws")) {
            return "whois.website.ws";
        } else if (name.endsWith(".xxx")) {
            return "whois.nic.xxx";
        } else if (name.endsWith(".xyz")) {
            return "whois.nic.xyz";
        } else if (name.endsWith(".yu")) {
            return "whois.ripe.net";
        } else if (name.endsWith(".za.com")) {
            return "whois.centralnic.com";
        } else {
            return null;
        }
    }
}
