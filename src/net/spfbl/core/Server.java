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

import net.spfbl.spf.SPF;
import net.spfbl.data.Provider;
import net.spfbl.data.NoReply;
import net.spfbl.data.Block;
import net.spfbl.data.White;
import net.spfbl.data.Trap;
import net.spfbl.data.Ignore;
import net.spfbl.whois.AutonomousSystem;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Handle;
import net.spfbl.whois.NameServer;
import net.spfbl.whois.Owner;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv4;
import net.spfbl.whois.SubnetIPv6;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadInfo;
import java.lang.management.ThreadMXBean;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.text.DecimalFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.Timer;
import java.util.TimerTask;
import java.util.TreeMap;
import java.util.concurrent.Semaphore;
import java.util.zip.GZIPOutputStream;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.naming.CommunicationException;
import javax.naming.LimitExceededException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.ServiceUnavailableException;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import static net.spfbl.core.Regex.isHostname;
import static net.spfbl.core.Regex.isValidIP;
import net.spfbl.data.Abuse;
import net.spfbl.data.CIDR;
import net.spfbl.data.DKIM;
import net.spfbl.data.Dictionary;
import net.spfbl.data.Generic;
import net.spfbl.data.FQDN;
import net.spfbl.data.FileStore;
import net.spfbl.data.Recipient;
import net.spfbl.data.Reputation;
import net.spfbl.data.URI;
import net.spfbl.service.ServerDNS;
import net.spfbl.service.ServerHTTP;
import net.spfbl.service.ServerP2P;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.commons.net.whois.WhoisClient;
import org.productivity.java.syslog4j.Syslog;
import org.productivity.java.syslog4j.SyslogIF;

/**
 * Representa um modelo de servidor com métodos comuns.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public abstract class Server extends Thread {
    
    /**
     * Varivável que determina se o serviço deve continuar rodando.
     */
    private boolean run = true;
    
    /**
     * Armazena todos os servidores intanciados.
     */
    private static final LinkedList<Server> SERVER_LIST = new LinkedList<>();
    
    /**
     * Instancia um servidor.
     * @param name nome do servidor e da thread.
     */
    protected Server(String name) {
        super(name);
        // Adiciona novo servidor na lista.
        SERVER_LIST.add(this);
    }
    
    protected boolean continueListenning() {
        return run;
    }
    
    /**
     * Carregamento de cache em disco.
     */
    public static void loadCache() {
        Client.load();
        NoReply.load();
        Owner.load();
        Domain.load();
        AutonomousSystem.load();
        SubnetIPv4.load();
        SubnetIPv6.load();
        Handle.load();
        NameServer.load();
        Peer.load();
        Provider.load();
        Ignore.load();
        Analise.load();
        Reverse.load();
        Generic.load();
        Block.load();
        White.load();
        Trap.load();
        Abuse.load();
        SPF.load();
        Defer.load();
        ServerDNS.load();
        User.load();
        ServerHTTP.load();
        ServerDNS.loadAbuse();
        FQDN.load();
        CIDR.load();
        net.spfbl.data.SPF.load();
        DKIM.load();
        Dictionary.load();
        Abuse.loadTXT();
        URI.load();
        net.spfbl.data.Domain.load();
        Recipient.load();
        System.gc();
    }
    
    private static Semaphore SEMAPHORE_STORE = new Semaphore(1);
    private static Semaphore SEMAPHORE_PROCESS = new Semaphore(1);
    
    private static class Store extends Thread {
        
        public Store() {
            super("BCKGROUND");
            super.setPriority(MIN_PRIORITY);
        }
        
        @Override
        public void run() {
            try {
                storeAll();
            } finally {
                SEMAPHORE_STORE.release();
                if (SEMAPHORE_PROCESS.tryAcquire()) {
                    try {
                        autoProcess();
                    } finally {
                        SEMAPHORE_PROCESS.release();
                    }
                }
            }
        }
    }
    
    public static boolean tryAcquireStoreCache() {
        return SEMAPHORE_STORE.tryAcquire();
    }
    
    public static void releaseStoreCache() {
        SEMAPHORE_STORE.release();
    }
    
    
    /**
     * Armazenamento de cache em disco.
     */
    public static boolean tryStoreCache() {
        if (SEMAPHORE_STORE.tryAcquire()) {
            new Store().start();
            return true;
        } else {
            return false;
        }
    }
    
    /**
     * Armazenamento de cache em disco.
     */
    private static void storeCache() {
        try {
            SEMAPHORE_STORE.acquire();
            try {
                storeAll();
            } finally {
                SEMAPHORE_STORE.release();
            }
        } catch (Exception ex) {
            Server.logError(ex);
        }
    }
        
    private static void storeAll() {
        Client.store();
        User.store();
        Peer.store();
        Provider.store();
        Ignore.store();
        Generic.store();
        Trap.store();
        NoReply.store();
        ServerDNS.store();
        White.store();
        Analise.store();
        Reverse.store();
        Defer.store();
        SPF.store();
        Owner.store();
        Domain.store();
        AutonomousSystem.store();
        SubnetIPv4.store();
        SubnetIPv6.store();
        Handle.store();
        NameServer.store();
        Core.store();
        Block.store();
        ServerHTTP.store();
        ServerDNS.storeAbuse();
        CIDR.store();
        FQDN.store();
        net.spfbl.data.SPF.store();
        DKIM.store();
        Dictionary.store();
        Abuse.store();
        URI.store();
        net.spfbl.data.Domain.store();
        Reputation.refreshTime();
        Recipient.store();
        System.gc();
    }
    
    private static void autoProcess() {
        Analise.checkAccessSMTP();
        Server.deleteLogExpired();
        User.storeDB();
        Core.autoClearHistory();
    }

    private static SecretKey privateKey = null;
    
    private static SecretKey getPrivateKey() {
        if (privateKey == null) {
            try {
                File file = new File("./data/server.key");
                if (file.exists()) {
                    try (FileInputStream fileInputStream = new FileInputStream(file)) {
                        privateKey = SerializationUtils.deserialize(fileInputStream);
                    }
                } else {
                    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                    keyGen.init(new SecureRandom());
                    SecretKey key = keyGen.generateKey();
                    try (FileOutputStream outputStream = new FileOutputStream(file)) {
                        SerializationUtils.serialize(key, outputStream);
                    }
                    privateKey = key;
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        return privateKey;
    }
    
    public static String encrypt(String message) throws ProcessException {
        if (message == null) {
            return null;
        } else {
            try {
                return encrypt(message.getBytes("UTF8"));
            } catch (Exception ex) {
                throw new ProcessException("ERROR: ENCRYPTION", ex);
            }
        }
    }
    
    public static String encrypt(ByteBuffer buffer) throws ProcessException {
        if (buffer == null) {
            return null;
        } else {
            return encrypt(buffer.array());
        }
    }
    
    public static String encrypt(byte[] byteArray) throws ProcessException {
        if (byteArray == null) {
            return null;
        } else {
            try {
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, getPrivateKey());
                byte[] code = cipher.doFinal(byteArray);
                return new String(Core.BASE64URLSAFE.encode(code));
            } catch (Exception ex) {
                throw new ProcessException("ERROR: ENCRYPTION", ex);
            }
        }
    }
    
    public static String encryptDES(byte[] byteArray) throws ProcessException {
        if (byteArray == null) {
            return null;
        } else {
            try {
                Cipher cipher = Cipher.getInstance("DES");
                cipher.init(Cipher.ENCRYPT_MODE, getPrivateKey());
                byte[] code = cipher.doFinal(byteArray);
                return new String(Core.BASE64URLSAFE.encode(code));
            } catch (Exception ex) {
                throw new ProcessException("ERROR: ENCRYPTION", ex);
            }
        }
    }
    
    public static String encryptHEX(byte[] byteArray) throws ProcessException {
        if (byteArray == null) {
            return null;
        } else {
            try {
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, getPrivateKey());
                byte[] code = cipher.doFinal(byteArray);
                return Hex.encodeHexString(code);
            } catch (Exception ex) {
                throw new ProcessException("ERROR: ENCRYPTION", ex);
            }
        }
    }
    
    public static String encrypt32(byte[] byteArray) throws ProcessException {
        if (byteArray == null) {
            return null;
        } else {
            try {
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, getPrivateKey());
                byte[] code = cipher.doFinal(byteArray);
                return Core.BASE32STANDARD.encodeAsString(code);
            } catch (Exception ex) {
                throw new ProcessException("ERROR: ENCRYPTION", ex);
            }
        }
    }
    
    public static String encryptURLSafe(byte[] byteArray) throws ProcessException {
        if (byteArray == null) {
            return null;
        } else {
            try {
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, getPrivateKey());
                byte[] code = cipher.doFinal(byteArray);
                return Core.BASE64URLSAFE.encodeAsString(code);
            } catch (Exception ex) {
                throw new ProcessException("ERROR: ENCRYPTION", ex);
            }
        }
    }
    
    public static String decrypt(String code) throws ProcessException {
        if (code == null) {
            return null;
        } else {
            try {
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
                byte[] message = cipher.doFinal(Core.BASE64URLSAFE.decode(code));
                return new String(message, "UTF8");
            } catch (Exception ex) {
                throw new ProcessException("ERROR: DECRYPTION", ex);
            }
        }
    }
    
    private static final Regex BASE64_REGEX = new Regex("^[a-zA-Z0-9_-]+$");
    
    public static boolean isValidTicket(String code) {
        if (code == null) {
            return false;
        } else if (code.length() < 32) {
            return false;
        } else if (BASE64_REGEX.matches(code)) {
            return decryptToByteArrayURLSafe(code) != null;
        } else {
            return false;
        }
    }
    
    public static byte[] decryptToByteArray32(String code) {
        if (code == null) {
            return null;
        } else {
            try {
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
                return cipher.doFinal(Core.BASE32STANDARD.decode(code));
            } catch (Exception ex) {
                return null;
            }
        }
    }
    
    public static byte[] decryptToByteArrayURLSafe(String code) {
        if (code == null) {
            return null;
        } else {
            try {
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
                return cipher.doFinal(Core.BASE64URLSAFE.decode(code));
            } catch (Exception ex) {
                return null;
            }
        }
    }
    
    public static byte[] decryptToByteArray(String code) throws ProcessException {
        if (code == null) {
            return null;
        } else {
            try {
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
                return cipher.doFinal(Core.BASE64STANDARD.decode(code));
            } catch (Exception ex) {
                throw new ProcessException("ERROR: DECRYPTION", ex);
            }
        }
    }
    
    /**
     * Constante de formatação da data no log.
     * Padrão ISO 8601
     * 
     * Um objeto SimpleDateFormat não é thread safety,
     * portanto é necessário utilizar sincronismo
     * nos métodos que o utilizam.
     */
    private static final LinkedList<SimpleDateFormat> FORMAT_DATE_LOG_LIST = new LinkedList<>();
    
    private static synchronized SimpleDateFormat pullLogDateFormat() {
        return FORMAT_DATE_LOG_LIST.poll();
    }
    
    private static synchronized void addLogDateFormat(SimpleDateFormat dateFormat) {
        if (dateFormat != null && FORMAT_DATE_LOG_LIST.size() < 4) {
            FORMAT_DATE_LOG_LIST.add(dateFormat);
        }
    }
    
    private static SimpleDateFormat createLogDateFormat() {
        SimpleDateFormat dateFormat = pullLogDateFormat();
        if (dateFormat == null) {
            return new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
        } else {
            return dateFormat;
        }
    }
    
    /**
     * Constante de formatação da data no ticket.
     * Baseado no padrão ISO 8601
     * 
     * Um objeto SimpleDateFormat não é thread safety,
     * portanto é necessário utilizar sincronismo
     * nos métodos que o utilizam.
     */
    private static final LinkedList<SimpleDateFormat> FORMAT_DATE_TICKET_LIST = new LinkedList<>();
    
    private static synchronized SimpleDateFormat pullTicketDateFormat() {
        return FORMAT_DATE_TICKET_LIST.poll();
    }
    
    private static synchronized void addTicketDateFormat(SimpleDateFormat dateFormat) {
        if (dateFormat != null && FORMAT_DATE_TICKET_LIST.size() < 4) {
            FORMAT_DATE_TICKET_LIST.add(dateFormat);
        }
    }
    
    public static String formatTicketDate(long time) {
        return formatTicketDate(new Date(time));
    }
    
    public static String formatTicketDate(Date date) {
        SimpleDateFormat dateFormat = pullTicketDateFormat();
        if (dateFormat == null) {
            dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSSZ");
        }
        try {
            return dateFormat.format(date);
        } finally {
            addTicketDateFormat(dateFormat);
        }
    }
    
    public static Date parseTicketDate(String value) throws ParseException {
        SimpleDateFormat dateFormat = pullTicketDateFormat();
        if (dateFormat == null) {
            dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSSZ");
        }
        try {
            return dateFormat.parse(value);
        } finally {
            addTicketDateFormat(dateFormat);
        }
    }
    
    private static long LAST_UNIQUE_TIME = 0;
    
    public static synchronized long getNewUniqueTime() {
        long time = System.currentTimeMillis();
        if (time <= LAST_UNIQUE_TIME) {
            // Não permite criar dois tickets 
            // exatamente com a mesma data para 
            // que o hash fique sempre diferente.
            time = LAST_UNIQUE_TIME + 1;
        }
        return LAST_UNIQUE_TIME = time;
    }
    
    public static String getNewTicketDate() {
        long time = getNewUniqueTime();
        return formatTicketDate(time);
    }
    
    /**
     * Constante que representa a quantidade de tempo de um dia em milisegundos.
     */
    public static final long MINUTE_TIME = 1000L * 60L;
    
    /**
     * Constante que representa a quantidade de tempo de um dia em milisegundos.
     */
    public static final long HOUR_TIME = MINUTE_TIME * 60L;
    
    /**
     * Constante que representa a quantidade de tempo de um dia em milisegundos.
     */
    public static final long DAY_TIME = HOUR_TIME * 24L;
    
    /**
     * Constante que representa a quantidade de tempo de uma semana em milisegundos.
     */
    public static final long WEEK_TIME = DAY_TIME * 7L;
        
    /**
     * O campo de latência do LOG tem apenas 4 digitos.
     * Serve para mostrar quais processamentos levam mais tempo
     * e para encontrar com mais facilidade códigos
     * do programa que não estão bem escritos.
     */
    private static final LinkedList<DecimalFormat> LATENCIA_FORMAT_LIST = new LinkedList<>();
    
    private static synchronized DecimalFormat pullLatenciaFormat() {
        return LATENCIA_FORMAT_LIST.poll();
    }
    
    private static synchronized void addLatenciaFormat(DecimalFormat decimalFormat) {
        if (decimalFormat != null && LATENCIA_FORMAT_LIST.size() < 4) {
            LATENCIA_FORMAT_LIST.add(decimalFormat);
        }
    }
    
    private static DecimalFormat createLatenciaFormat() {
        DecimalFormat decimalFormat = pullLatenciaFormat();
        if (decimalFormat == null) {
            return new DecimalFormat("00000");
        } else {
            return decimalFormat;
        }
    }
    
    /**
     * Registra uma linha de LOG
     * 
     * Utiliza os seguintes campos:
     *    - Data do início do processo;
     *    - Latência do processamento em milisegundos com 4 dígitos fixos;
     *    - Tipo de registro de LOG com 5 caracteres fixos e
     *    - Mensagem do LOG.
     * 
     * Nenhum processamento deve durar mais que 9999 milisegundos.
     * Por este motivo o valor foi limitado a 4 digitos.
     * Se acontecer do valor ser maior que 9999, significa que o código 
     * tem graves problemas de eficiência e deve ser revisto com urgência.
     * Outros valores grandes abaixo deste limite podem 
     * ser investigados com cautela.
     * 
     * @param time data exata do inicio do processamento.
     * @param type tipo de registro de LOG.
     * @param message a mensagem do registro de LOG.
     */
    public static void log(
            long time, Core.Level level, String type,
            Long key, String message, String result
    ) {
        if (level != null) {
            if (level.ordinal() <= Core.LOG_LEVEL.ordinal()) {
                int latency = (int) (System.currentTimeMillis() - time);
                if (latency > 99999) {
                    // Para manter a formatação correta no LOG,
                    // Registrar apenas latências até 99999, que tem 5 digitos.
                    latency = 99999;
                } else if (latency < 0) {
                    latency = 0;
                }
                if (message != null) {
                    message = message.replace("\r", "\\r");
                    message = message.replace("\n", "\\n");
                    message = message.replace("\t", "\\t");
                }
                if (result != null) {
                    result = result.replace("\r", "\\r");
                    result = result.replace("\n", "\\n");
                    result = result.replace("\t", "\\t");
                }
                SimpleDateFormat dateFormat = createLogDateFormat();
                DecimalFormat latenciaFormat = createLatenciaFormat();
                try {
                    String dateTime = dateFormat.format(new Date(time));
                    String text = dateTime + " " + latenciaFormat.format(latency)
                            + " " + Thread.currentThread().getName()
                            + " " + type
                            + (key == null ? "" : " #" + Long.toString(key, 32))
                            + " " + message
                            + (result == null ? "" : " => " + result);
                    FileStore logFile = getLogFile(
                            dateTime.substring(0,10)
                    );
                    if (logFile == null) {
                        System.out.println(text);
                    } else {
                        logFile.append(text);
                    }
                } finally {
                    addLogDateFormat(dateFormat);
                    addLatenciaFormat(latenciaFormat);
                }
            }
            if (syslog != null) {
                logSyslog(level, type, message, result);
            }
        }
    }
    
    public static synchronized void logSyslog(
            Core.Level level, String type,
            String message, String result
    ) {
        if (syslog != null) {
            if (Core.hasHostname()) {
                syslog.getConfig().setLocalName(Core.getHostname());
            }
            syslog.getConfig().setIdent(type);
            String log = message + (result == null ? "" : " => " + result);
            switch (level) {
                case ERROR:
                    syslog.error(log);
                    break;
                case WARN:
                    syslog.warn(log);
                    break;
                case INFO:
                    syslog.info(log);
                    break;
                case DEBUG:
                    syslog.debug(log);
                    break;
            }
        }
    }
    
    private static File LOG_FOLDER = null;
    private static String logDate = null;
    private static FileStore logFile = null;
    private static SyslogIF syslog = null;
    private static short logExpires = 7;
    
    public static synchronized void setSyslog(Properties properties) {
        if (properties != null) {
            String protocol = properties.getProperty("log_server_protocol");
            String hostname = properties.getProperty("log_server_host");
            String port = properties.getProperty("log_server_port");
            String facility = properties.getProperty("log_server_facility");
            if (protocol != null) {
                protocol = protocol.toLowerCase();
                if (!protocol.equals("udp") && protocol.equals("tcp")) {
                    protocol = null;
                    Server.logError("invalid Syslog server protocol '" + protocol + "'.");
                }
            }
            if (hostname != null) {
                if (hostname.length() == 0) {
                    hostname = null;
                } else if (isHostname(hostname)) {
                    hostname = Domain.extractHost(hostname, false);
                } else if (isValidIP(hostname)) {
                    hostname = Subnet.normalizeIP(hostname);
                } else {
                    hostname = null;
                    Server.logError("invalid Syslog server host '" + hostname + "'.");
                }
            }
            Integer portInt;
            if (port == null || port.length() == 0) {
                portInt = null;
            } else {
                try {
                    portInt = Integer.parseInt(port);
                } catch (Exception ex) {
                    portInt = null;
                    Server.logError("invalid Syslog server port '" + port + "'.");
                }
            }
            if (protocol != null && hostname != null && portInt != null) {
                syslog = Syslog.getInstance(protocol);
                syslog.getConfig().setHost(hostname);
                syslog.getConfig().setPort(portInt);
                syslog.getConfig().setCharSet("UTF-8");
                if (facility != null) {
                    facility = facility.toLowerCase();
                    if (facility.equals("mail")) {
                        syslog.getConfig().setFacility("mail");
                    } else if (facility.startsWith("local") && facility.length() == 6 && Character.isDigit(facility.charAt(5))) {
                        syslog.getConfig().setFacility(facility);
                    } else {
                        Server.logError("invalid Syslog facility '" + facility + "'.");
                    }
                }
            }
        }
    }
    
    public static synchronized void setLogFolder(String path) {
        if (path == null) {
            Server.LOG_FOLDER = null;
        } else {
            File folder = new File(path);
            if (folder.exists()) {
                if (folder.isDirectory()) {
                    Server.LOG_FOLDER = folder;
                } else {
                    Server.logError("'" + path + "' is not a folder.");
                }
            } else {
                Server.logError("folder '" + path + "' not exists.");
            }
        }
    }
    
    public static void setLogExpires(String expires) {
        if (expires != null && expires.length() > 0) {
            try {
                setLogExpires(Integer.parseInt(expires));
            } catch (Exception ex) {
                Server.logError("invalid LOG expires integer value '" + expires + "'.");
            }
        }
    }
    
    public static synchronized void setLogExpires(int expires) {
        if (expires < 1 || expires > Short.MAX_VALUE) {
            Server.logError("invalid LOG expires integer value '" + expires + "'.");
        } else {
            Server.logExpires = (short) expires;
        }
    }
    
    public static void setLogDNS(String mustLog) {
        if (mustLog != null && mustLog.length() > 0) {
            ServerDNS.setLog(Boolean.parseBoolean(mustLog));
        }
    }
    
    public static void setLogP2P(String mustLog) {
        if (mustLog != null && mustLog.length() > 0) {
            ServerP2P.setLog(Boolean.parseBoolean(mustLog));
        }
    }
    
    private static FileStore getLogFile(String date) {
        try {
            if (date == null) {
                return null;
            } else if (LOG_FOLDER == null || !LOG_FOLDER.exists()) {
                return null;
            } else {
                return createLogFile(date);
            }
        } catch (Exception ex) {
            return null;
        }
    }
    
    private synchronized static FileStore createLogFile(String date) throws IOException {
        if (logFile == null || logDate == null) {
            logDate = date;
            File file = new File(LOG_FOLDER, "spfbl." + date + ".log");
            logFile = new FileStore(file);
            logFile.start();
            return logFile;
        } else if (logDate.equals(date)) {
            return logFile;
        } else {
            logFile.close();
            logDate = date;
            File file = new File(LOG_FOLDER, "spfbl." + date + ".log");
            logFile = new FileStore(file);
            logFile.start();
            return logFile;
        }
    }
    
    private static final FilenameFilter logFilter = new FilenameFilter() {
        @Override
        public boolean accept(File dir, String name) {
            return name.startsWith("spfbl.") && (name.endsWith(".log") || name.endsWith(".log.gz"));
        }
    };
    
    private static void deleteLogExpired() {
        if (Core.isRunning()) {
            if (LOG_FOLDER != null && LOG_FOLDER.exists()) {
                Server.logTrace("deleting expired log files.");
                for (File logFileLocal : LOG_FOLDER.listFiles(logFilter)) {
                    long lastModified = logFileLocal.lastModified();
                    long period = System.currentTimeMillis() - lastModified;
                    int days = (int) (period / (1000 * 60 * 60 * 24));
                    if (days > logExpires) {
                        if (logFileLocal.delete()) {
                            Server.logInfo("the log file '" + logFileLocal.getName() + "' was deleted.");
                        } else {
                            Server.logError("the log file '" + logFileLocal.getName() + "' could not be deleted.");
                        }
                    } else if (days > 0) {
                        String name = logFileLocal.getName();
                        if (name.endsWith(".log")) {
                            File newFile = new File(LOG_FOLDER, name + ".gz");
                            try (GZIPOutputStream out = new GZIPOutputStream(new FileOutputStream(newFile))) {
                                try (FileInputStream in = new FileInputStream(logFileLocal)) {
                                    byte[] buffer = new byte[1024];
                                    int len;
                                    while ((len = in.read(buffer)) != -1) {
                                        out.write(buffer, 0, len);
                                    }
                                }
                                newFile.setLastModified(lastModified);
                                logFileLocal.delete();
                            } catch (Exception ex) {
                                Server.logError(ex);
                            }
                        }
                    }
                }
            }
        }
    }
    
    private static void log(
            long time,
            Core.Level level,
            String type,
            Long key,
            Throwable ex
    ) {
        if (ex != null) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PrintStream printStream = new PrintStream(baos);
            ex.printStackTrace(printStream);
            printStream.close();
            log(time, level, type, key, baos.toString(), (String) null);
        }
    }
    
    /**
     * Registra as mensagens para informação.
     * @param message a mensagem a ser registrada.
     */
    public static void logInfo(String message) {
        log(System.currentTimeMillis(), Core.Level.INFO, "INFOR",
                (Long) null, message, (String) null);
    }
    
    /**
     * Registra as mensagens para depuração.
     * @param message a mensagem a ser registrada.
     */
    public static void logDebug(Long timeKey, String message) {
        log(System.currentTimeMillis(), Core.Level.DEBUG, "DEBUG",
                timeKey, message, (String) null);
    }
    
    public static void logWarning(String message) {
        log(System.currentTimeMillis(), Core.Level.WARN, "WARNG", (Long) null, message, (String) null);
    }
    
    public static void logAcme(String message) {
        log(System.currentTimeMillis(), Core.Level.DEBUG, "ACMEP", (Long) null, message, (String) null);
    }
    
    public static void logSendSMTP(String message) {
        log(System.currentTimeMillis(), Core.Level.DEBUG, "SMTPS", (Long) null, message, (String) null);
    }
    
    /**
     * Registra as mensagens para depuração de código.
     * @param message a mensagem a ser registrada.
     */
    public static void logTrace(String message) {
        log(System.currentTimeMillis(), Core.Level.TRACE, "TRACE", (Long) null, message, (String) null);
    }
    
    public static String getThreadStack() {
        StringBuilder builder = new StringBuilder();
        ThreadMXBean tmxb = ManagementFactory.getThreadMXBean();
        TreeMap<Long,Long> threadMap = new TreeMap<>();
        long cpuTimeTotal = 0;
        for (long threadID : tmxb.getAllThreadIds()) {
            long cpuTime = tmxb.getThreadCpuTime(threadID);
            if (cpuTime > 0) {
                cpuTimeTotal += cpuTime;
                threadMap.put(threadID, cpuTime);
            }
        }
        for (ThreadInfo info : tmxb.dumpAllThreads(true, true)) {
            long threadID = info.getThreadId();
            Long cpuTime = threadMap.get(threadID);
            if (cpuTime == null) {
                builder.append("cpu:0 ");
            } else {
                long cpuUsage = 100 * cpuTime / cpuTimeTotal;
                builder.append("cpu:");
                builder.append(cpuUsage);
                builder.append(' ');
            }
            String text = info.toString();
            builder.append(text);
            if (text.endsWith("\n\t...\n\n")) {
                for (StackTraceElement element : info.getStackTrace()) {
                    text = element.toString();
                    builder.append("\tat ");
                    builder.append(text);
                    builder.append('\n');
                }
                builder.append('\n');
            }
        }
        return builder.toString();
    }
    
    public static void logThreadStack() {
        Core.Level level = Core.Level.DEBUG;
        if (level.ordinal() <= Core.LOG_LEVEL.ordinal()) {
            ThreadMXBean tmxb = ManagementFactory.getThreadMXBean();
            ThreadInfo[] threads = tmxb.dumpAllThreads(true, true);
            for (ThreadInfo info : threads) {
                long threadID = info.getThreadId();
                long cpuTime = tmxb.getThreadCpuTime(threadID);
                String text = "cpu:" + cpuTime + " " + info.toString();
                log(System.currentTimeMillis(), level, "STACK", (Long) null, text, (String) null);
                if (text.endsWith("\n\t...\n\n")) {
                    for (StackTraceElement element : info.getStackTrace()) {
                        log(System.currentTimeMillis(), level, "STACK", (Long) null, element.toString(), (String) null);
                    }
                }
            }
        }
    }
    
    /**
     * Registra as mensagens para depuração de código.
     * @param message a mensagem a ser registrada.
     */
    public static void logTrace(long time, String message) {
        log(time, Core.Level.TRACE, "TRACE", (Long) null, message, (String) null);
    }
    
    /**
     * Registra as mensagens de manipulação do banco de dados.
     * @param message a mensagem a ser registrada.
     */
    public static void logMySQL(String message) {
        log(System.currentTimeMillis(), Core.Level.DEBUG, "MYSQL", (Long) null, message, (String) null);
    }
    
    /**
     * Registra as mensagens de manipulação do banco de dados.
     * @param message a mensagem a ser registrada.
     */
    public static void logMySQL(long time, String message) {
        log(time, Core.Level.DEBUG, "MYSQL", (Long) null, message, null);
    }
    
    /**
     * Registra as mensagens de manipulação do banco de dados.
     * @param message a mensagem a ser registrada.
     */
    public static void logMySQL(long time, String message, String result) {
        log(time, Core.Level.DEBUG, "MYSQL", (Long) null, message, result);
    }
    
    /**
     * Registra as mensagens de manipulação do banco de dados.
     * @param message a mensagem a ser registrada.
     */
    public static void logMySQL(long time, String message, SQLException ex) {
        String result = "ERROR " + ex.getErrorCode() + " " + ex.getMessage();
        log(time, Core.Level.DEBUG, "MYSQL", (Long) null, message, result);
    }
    
    /**
     * Registra as mensagens de manipulação do banco de dados.
     * @param statement the statement executed.
     */
    public static void logMySQL(long time, PreparedStatement statement, String result) {
        String message = statement.toString();
        int beginIndex = message.indexOf(' ') + 1;
        int endIndex = message.length();
        message = message.substring(beginIndex, endIndex);
        log(time, Core.Level.DEBUG, "MYSQL", (Long) null, message, result);
    }
    
    /**
     * Registra as mensagens de manipulação do banco de dados.
     * @param statement the statement executed.
     */
    public static void logMySQL(long time, PreparedStatement statement, SQLException ex) {
        String message = statement.toString();
        int beginIndex = message.indexOf(' ') + 1;
        int endIndex = message.length();
        message = message.substring(beginIndex, endIndex);
        String result = "ERROR " + ex.getErrorCode() + " " + ex.getMessage();
        log(time, Core.Level.DEBUG, "MYSQL", (Long) null, message, result);
    }
    
    /**
     * Registra as gravações de cache em disco.
     * @param file o arquivo armazenado.
     */
    public static void logStore(long time, File file) {
        log(time, Core.Level.INFO, "STORE", (Long) null, file.getName(), (String) null);
    }
    
    /**
     * Registra os carregamentos de cache no disco.
     * @param file o arquivo carregado.
     */
    public static void logLoad(long time, File file) {
        log(time, Core.Level.INFO, "LOADC", (Long) null, file.getName(), (String) null);
    }
    
    public static void logPeerSend(long time,
            String address, String token, String result) {
        log(time, Core.Level.DEBUG, "PEERS", address, (Long) null, token, result);
    }
    
    /**
     * Registra as consultas de mecanismo A de SPF.
     */
    public static void logMecanismA(long time, 
            String host, String result) {
        log(time, Core.Level.DEBUG, "SPFMA", (Long) null, host, result);
    }
    
    /**
     * Registra as consultas de mecanismo MX de SPF.
     */
    public static void logMecanismMX(long time, 
            String host, String result) {
        log(time, Core.Level.DEBUG, "SPFMX", (Long) null, host, result);
    }
    
    /**
     * Registra interações de atrazo programado.
     */
    public static void logDefer(long time, 
            String id, String result) {
        log(time, Core.Level.DEBUG, "DEFER", (Long) null, id, result);
    }
    
    /**
     * Registra verificações de DNS reverso.
     */
    public static void logReverseDNS(long time, 
            String ip, String result) {
        log(time, Core.Level.DEBUG, "DNSRV", (Long) null, ip, result);
    }
    
    /**
     * Registra as mensagens de erro.
     * @param message a mensagem a ser registrada.
     */
    public static void logError(String message) {
        log(System.currentTimeMillis(), Core.Level.ERROR, "ERROR",
                (Long) null, message, (String) null);
    }
    
    public static void logDebug(String message) {
        log(System.currentTimeMillis(), Core.Level.DEBUG, "DEBUG",
                (Long) null, message, (String) null);
    }
    
    /**
     * Registra as mensagens de erro.
     * Uma iniciativa para formalização das mensagens de log.
     * @param ex a exceção a ser registrada.
     */
    public static void logError(Throwable ex) {
        log(System.currentTimeMillis(), Core.Level.ERROR, "ERROR", (Long) null, ex);
    }
    
    /**
     * Registra as consultas ao SPF do host 
     * que não foram encontrados erros de sintaxe.
     * Uma iniciativa para formalização das mensagens de log.
     * @param hostname o nome do host.
     * @param result o resultado SPF do host.
     */
    public static void logLookupSPF(
            long time, String hostname, String result) {
        log(time, Core.Level.DEBUG, "SPFLK", (Long) null, hostname, result);
    }
    
    public static void logQueryP2PUDP(long time,
            InetAddress ipAddress, String query, String result) {
        logQuery(time, "P2PUDP", ipAddress, (Long) null, query, result);
    }
    
    /**
     * Registra as consultas ao DNSBL do host.
     * Uma iniciativa para formalização das mensagens de log.
     * @param query a expressão da consulta.
     * @param result o resultado a ser registrado.
     */
    public static void logQueryDNSBL(
            long time,
            InetAddress ipAddress, String query, String result
    ) {
        logQuery(time, "DNSBL", ipAddress, (Long) null, query, result);
    }
    
    /**
     * Registra os resultados do WHOIS.
     * Uma iniciativa para formalização das mensagens de log.
     * @param server o servidor WHOIS.
     * @param query a expressão da consulta.
     * @param result o resultado a ser registrado.
     */
    public static void logWhois(long time,
            String server, String query, String result) {
        log(time, Core.Level.DEBUG, "WHOIS", (Long) null, server + " " + query, result);
    }
    
    /**
     * Registra as mensagens de consulta.
     * Uma iniciativa para formalização das mensagens de log.
     * @param time data exatata no inicio do processamento.
     * @param ipAddress o IP do cliente da conexão.
     * @param query a expressão da consulta.
     * @param result a expressão do resultado.
     */
    public static void logQuery(
            long time,
            String type,
            InetAddress ipAddress,
            Long timeKey,
            String query, String result
    ) {
        String origin = Client.getOrigin(ipAddress, "DNSBL");
        if (query == null) {
            log(time, Core.Level.INFO, type, timeKey, origin + ":", result);
        } else {
            log(time, Core.Level.INFO, type, timeKey, origin + ": " + query, result);
        }
    }
    
    public static void logQuery(
            long time,
            String type,
            Long timeKey,
            String client,
            Set<String> tokenSet
    ) {
        String message;
        if (tokenSet == null || tokenSet.isEmpty()) {
            message = "";
        } else {
            message = null;
            for (String token : tokenSet) {
                if (message == null) {
                    message = token;
                } else {
                    message += ' ' + token;
                }
            }
        }
        log(
                time, Core.Level.INFO, type, timeKey,
                (client == null ? "" : client + ": ") + message,
                null
        );
    }
    
    public static void log(
            long time,
            Core.Level level,
            String type,
            String client,
            Long timeKey,
            String query,
            Set<String> tokenSet,
            String recipient
    ) {
        String result;
        if (tokenSet == null || tokenSet.isEmpty()) {
            result = "";
        } else {
            result = null;
            for (String token : tokenSet) {
                if (result == null) {
                    result = token;
                } else {
                    result += ' ' + token;
                }
            }
            if (recipient != null) {
                result += " >" + recipient;
            }
        }
        log(time, level, type, client, timeKey, query, result);
    }
    
    public static void log(
            long time,
            Core.Level level,
            String type,
            String client,
            Long timeKey,
            String query,
            String result
    ) {
        log(
                time, level, type, timeKey,
                (client == null ? "" : client + ": ") + query,
                result
        );
    }
    
    public static void logQuery(
            long time,
            String type,
            String client,
            Long timeKey,
            String query,
            String result
    ) {
        logQuery(
                time,
                Core.Level.INFO,
                type,
                client,
                timeKey,
                query,
                result
        );
    }
    
    public static void logQuery(
            long time,
            Core.Level level,
            String type,
            String client,
            Long timeKey,
            String query,
            String result
    ) {
        if (result != null && result.length() > 1024) {
            int index1 = result.indexOf('\n', 1024);
            int index2 = result.indexOf(' ', 1024);
            int index = Math.min(index1, index2);
            index = Math.max(index, 1024);
            result = result.substring(0, index) + "... too long";
        }
        log(
                time, level, type, timeKey,
                (client == null ? "" : client + ": ") + query,
                result
        
        );
    }
    
    /**
     * Registra as mensagens de comando administrativo.
     * Uma iniciativa para formalização das mensagens de log.
     * @param ipAddress o IP da conexão.
     * @param command a expressão do comando.
     * @param result a expressão do resultado.
     */
    public static void logAdministration(long time,
            InetAddress ipAddress, String command, String result) {
        String origin = Client.getOrigin(ipAddress, "SPFBL");
        if (result != null && result.length() > 1024) {
            int index1 = result.indexOf('\n', 1024);
            int index2 = result.indexOf(' ', 1024);
            int index = Math.min(index1, index2);
            index = Math.max(index, 1024);
            result = result.substring(0, index) + "... too long";
        }
        log(time, Core.Level.INFO, "ADMIN", (Long) null, origin + ": " + command, result);
    }
    
    /**
     * Desliga todos os servidores instanciados.
     */
    public static boolean shutdown() {
        // Inicia finalização dos servidores.
        Server.logInfo("interrupting analises...");
        Analise.interrupt();
        Server.logInfo("interrupting user theads...");
        User.interrupt();
        Server.logInfo("shutting down server...");
        for (Server server : SERVER_LIST) {
            server.run = false;
        }
        boolean closed = true;
        for (Server server : SERVER_LIST) {
            try {
                server.close();
            } catch (Exception ex) {
                closed = false;
                Server.logError(ex);
            }
        }
        // Finaliza timer local.
        cancelWhoisSemaphoreTimer();
        // Finaliza timer SPF.
        Core.cancelTimer();
        User.terminateThread();
        FQDN.terminateThread();
        CIDR.terminateThread();
        net.spfbl.data.SPF.terminateThread();
        DKIM.terminateThread();
        Dictionary.terminateThread();
        Block.terminateThread();
        Generic.terminateThread();
        Abuse.terminateThread();
        net.spfbl.data.URI.terminateThread();
        Recipient.terminateThread();
        // Armazena os registros em disco.
        storeCache();
        // Fecha pooler de conexão MySQL.
        Core.closeConnectionPooler();
        User.closeAllHistory();
        if (syslog != null) {
            // Fecha conexão Syslog.
            syslog.shutdown();
        }
        return closed;
    }
    
    /**
     * Finaliza servidor liberando memória e respectivos recursos.
     * @throws Exception se houver falha durante o fechamento do servidor.
     */
    protected abstract void close() throws Exception;
    
    /**
     * Timer que controla a liberação dos semáforos do WHOIS.
     */
    private static Timer WHOIS_SEMAPHORE_TIMER = null;
    
    private static synchronized Timer getWhoisSemaphoreTimer() {
        if (WHOIS_SEMAPHORE_TIMER == null) {
            WHOIS_SEMAPHORE_TIMER = new Timer("TIMEWHOIS");
        }
        return WHOIS_SEMAPHORE_TIMER;
    }
    
    private static synchronized void cancelWhoisSemaphoreTimer() {
        if (WHOIS_SEMAPHORE_TIMER != null) {
            WHOIS_SEMAPHORE_TIMER.cancel();
        }
    }
    
    /**
     * Semáphoro que controla o número máximo de consultas no WHOIS.
     * Controla a taxa de 30 consultas no intervalo de 5 minutos.
     */
    private static final int WHOIS_QUERY_LIMIT = 30; // Taxa de 30 consultas.
    private static final int WHOIS_FREQUENCY = 5 * 60 * 1000; // Libera o direito à consulta em 5 min.
    private static final Semaphore WHOIS_QUERY_SEMAPHORE = new Semaphore(WHOIS_QUERY_LIMIT);
    
    /**
     * Classe de tarefa que adquire e libera o semáforo de consulta comum do WHOIS.
     * Controla a taxa de 30 consultas no intervalo de 5 minutos.
     */
    private static class WhoisSemaphore extends TimerTask {
        
        public WhoisSemaphore() throws ProcessException {
            if (!WHOIS_QUERY_SEMAPHORE.tryAcquire()) {
                // Estouro de limite de consultas ao WHOIS.
                throw new ProcessException("ERROR: WHOIS QUERY LIMIT");
            }
        }
        
        @Override
        public void run() {
            WHOIS_QUERY_SEMAPHORE.release();
        }
    }
    
    /**
     * Adquire o direito a uma consulta comum no WHOIS.
     * Controla a taxa de 30 consultas no intervalo de 5 minutos.
     * @throws ProcessException se houver falha no processo.
     */
    public static void acquireWhoisQuery() throws ProcessException {
        WhoisSemaphore whoisSemaphore = new WhoisSemaphore();
        Timer timer = getWhoisSemaphoreTimer();
        timer.schedule(whoisSemaphore, WHOIS_FREQUENCY);
        timer.purge(); // Libera referências processadas.
    }
    
    /**
     * Remove o direito a uma consulta comum no WHOIS por um dia.
     * As vezes a consulta WHOIS restringe as consultas.
     * Este método é uma forma de reduzir drasticamente a frequência.
     * @throws ProcessException se houver falha no processo.
     */
    public static void removeWhoisQueryDay() throws ProcessException {
        WhoisSemaphore whoisSemaphore = new WhoisSemaphore();
        Timer timer = getWhoisSemaphoreTimer();
        timer.schedule(whoisSemaphore, DAY_TIME);
    }
    
    /**
     * Remove o direito a uma consulta comum no WHOIS por uma hora.
     * As vezes a consulta WHOIS restringe as consultas.
     * Este método é uma forma de reduzir drasticamente a frequência.
     * @throws ProcessException se houver falha no processo.
     */
    public static void removeWhoisQueryHour() throws ProcessException {
        WhoisSemaphore whoisSemaphore = new WhoisSemaphore();
        Timer timer = getWhoisSemaphoreTimer();
        timer.schedule(whoisSemaphore, HOUR_TIME);
    }
    
    /**
     * Semáphoro que controla o número máximo de consultas no WHOIS.
     * Controla a taxa de 30 consultas no intervalo de 24 horas.
     */
    private static final Semaphore WHOIS_ID_QUERY_SEMAPHORE = new Semaphore(30);
    
    /**
     * Classe de tarefa que adquire e libera o semáforo de consulta comum do WHOIS.
     * Controla a taxa de 30 consultas no intervalo de 24 horas.
     */
    private static class WhoisIDSemaphore extends TimerTask {
        
        public WhoisIDSemaphore() throws ProcessException {
            if (!WHOIS_ID_QUERY_SEMAPHORE.tryAcquire()) {
                // Estouro de limite de consultas ao WHOIS.
                throw new ProcessException("ERROR: WHOIS QUERY LIMIT");
            }
        }
        
        @Override
        public void run() {
            WHOIS_ID_QUERY_SEMAPHORE.release();
        }
    }
    
    /**
     * Adquire o direito a uma consulta de identificação no WHOIS.
     * Controla a taxa de 30 consultas no intervalo de 24 horas.
     * @throws ProcessException se houver falha no processo.
     */
    private static void acquireWhoisIDQuery() throws ProcessException {
        WhoisIDSemaphore whoisIDSemaphore = new WhoisIDSemaphore();
        Timer timer = getWhoisSemaphoreTimer();
        timer.schedule(whoisIDSemaphore, DAY_TIME); // Libera o direito à consulta em 24h.
        timer.purge(); // Libera referências processadas.
    }
    
    /**
     * Semáphoro que controla o número máximo de conexões simutâneas no WHOIS.
     * Limite de 2 conexões simultâneas por IP de origem.
     */
    private static final Semaphore WHOIS_CONNECTION_SEMAPHORE = new Semaphore(2);
    
    public static void removeWhoisConnection() {
        WHOIS_CONNECTION_SEMAPHORE.tryAcquire();
    }
    
    /**
     * Consulta de identificação no WHOIS.
     * Controla a taxa de 30 consultas no intervalo de 24 horas.
     * @param query a consulta a ser realizada.
     * @param server o servidor que contém a informação.
     * @return o resultado do WHOIS para a consulta.
     * @throws ProcessException se houver falha no processamento da informação.
     */
    public static String whoisID(String query, String server) throws ProcessException {
        if (WHOIS_BR.length() == 0) {
            return null;
        } else {
            long time = System.currentTimeMillis();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            try {
                if (WHOIS_CONNECTION_SEMAPHORE.tryAcquire()) {
                    try {
                        acquireWhoisIDQuery();
                        WhoisClient whoisClient = new WhoisClient();
                        try {
                            whoisClient.setDefaultTimeout(3000);
                            whoisClient.connect(server);
                            InputStream inputStream = whoisClient.getInputStream(query);
                            int code;
                            while ((code = inputStream.read()) != -1) {
                                outputStream.write(code);
                            }
                        } finally {
                            whoisClient.disconnect();
                        }
                    } finally {
                        WHOIS_CONNECTION_SEMAPHORE.release();
                    }
                } else {
                    throw new ProcessException("TOO MANY CONNECTIONS");
                }
            } catch (ProcessException ex) {
                throw ex;
            } catch (Exception ex) {
                throw new ProcessException("WHOIS CONNECTION FAIL", ex);
            }
            try {
                String result = outputStream.toString("ISO-8859-1");
                logWhois(time, server, query, result);
                return result;
            } catch (UnsupportedEncodingException ex) {
                throw new ProcessException("ERROR: ENCODING", ex);
            }
        }
    }
    
    /**
     * Constante do servidor WHOIS brasileiro definida na partida do sistema.
     */
    public static String WHOIS_BR = null;
    
    protected static synchronized void setServerWHOISBR(String server) {
        if (WHOIS_BR == null) {
            if (server == null || server.length() == 0) {
                WHOIS_BR = "whois.nic.br";
            } else if (server.equals("NONE")) {
                WHOIS_BR = "";
            } else if ((server = Domain.normalizeHostname(server, false)) != null) {
                WHOIS_BR = server;
            }
            SubnetIPv4.init();
            SubnetIPv6.init();
        }
    }

    private static final LinkedList<InitialDirContext> IDC_LIST = new LinkedList<>();
    
    private synchronized static InitialDirContext pollInitialDirContext() {
        return IDC_LIST.poll();
    }
    
    private synchronized static void addInitialDirContext(InitialDirContext idc) {
        if (idc != null && IDC_LIST.size() < 4) {
            IDC_LIST.add(idc);
        }
    }
    
    public static Attributes getAttributesDNS(String hostname, String... types) throws NamingException {
        return getAttributesDNS(null, hostname, types);
    }
    
    public static Attributes getAttributesDNS(String server, String hostname, String[] types) throws NamingException {
        InitialDirContext idc = pollInitialDirContext();
        if (idc == null) {
            Hashtable<String,String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
//            env.put("java.naming.provider.url", "dns://ns.dnssek.org");
            env.put("com.sun.jndi.dns.timeout.initial", "1000");
            env.put("com.sun.jndi.dns.timeout.retries", "1");
            idc = new InitialDirContext(env);
        }
        try {
            if (server == null) {
                if (DNS_PROVIDER_PRIMARY != null && DNS_PROVIDER_PRIMARY_TIME > System.currentTimeMillis()) {
                    try {
                        if (DNS_PROVIDER_PRIMARY.contains(":")) {
                            return idc.getAttributes("dns://[" + DNS_PROVIDER_PRIMARY + "]/" + hostname, types);
                        } else {
                            return idc.getAttributes("dns://" + DNS_PROVIDER_PRIMARY + "/" + hostname, types);
                        }
                    } catch (NameNotFoundException ex) {
                        throw ex;
                    } catch (CommunicationException ex) {
                        DNS_PROVIDER_PRIMARY_TIME = System.currentTimeMillis() + Server.HOUR_TIME;
                        Server.logError(ex);
                    } catch (ServiceUnavailableException ex) {
                        DNS_PROVIDER_PRIMARY_TIME = System.currentTimeMillis() + Server.HOUR_TIME;
                        Server.logError(ex);
                    } catch (LimitExceededException ex) {
                        DNS_PROVIDER_PRIMARY_TIME = System.currentTimeMillis() + Server.HOUR_TIME;
                        Server.logError(ex);
                    } catch (NamingException ex) {
                        Server.logError(ex);
                    }
                }
                if (DNS_PROVIDER_SECONDARY != null && DNS_PROVIDER_SECONDARY_TIME > System.currentTimeMillis()) {
                    try {
                        if (DNS_PROVIDER_SECONDARY.contains(":")) {
                            return idc.getAttributes("dns://[" + DNS_PROVIDER_SECONDARY + "]/" + hostname, types);
                        } else {
                            return idc.getAttributes("dns://" + DNS_PROVIDER_SECONDARY + "/" + hostname, types);
                        }
                    } catch (NameNotFoundException ex) {
                        throw ex;
                    } catch (CommunicationException ex) {
                        DNS_PROVIDER_SECONDARY_TIME = System.currentTimeMillis() + Server.HOUR_TIME;
                        Server.logError(ex);
                    } catch (ServiceUnavailableException ex) {
                        DNS_PROVIDER_SECONDARY_TIME = System.currentTimeMillis() + Server.HOUR_TIME;
                        Server.logError(ex);
                    } catch (LimitExceededException ex) {
                        DNS_PROVIDER_SECONDARY_TIME = System.currentTimeMillis() + Server.HOUR_TIME;
                        Server.logError(ex);
                    } catch (NamingException ex) {
                        Server.logError(ex);
                    }
                }
                return idc.getAttributes("dns:/" + hostname, types);
            } else {
                if (server.contains(":")) {
                    return idc.getAttributes("dns://[" + server + "]/" + hostname, types);
                } else {
                    return idc.getAttributes("dns://" + server + "/" + hostname, types);
                }
            }
        } finally {
            addInitialDirContext(idc);
        }
    }
    
    private static String DNS_PROVIDER_PRIMARY = null;
    private static String DNS_PROVIDER_SECONDARY = null;
    
    private static long DNS_PROVIDER_PRIMARY_TIME = 0L;
    private static long DNS_PROVIDER_SECONDARY_TIME = 0L;
    
    public static void setPrimaryProviderDNS(String ip) {
        if (ip != null && ip.length() > 0) {
            if (isValidIP(ip)) {
                Server.DNS_PROVIDER_PRIMARY = Subnet.normalizeIP(ip);
                Server.logInfo("using " + ip + " as fixed primary DNS provider.");
            } else {
                Server.logError("invalid primary DNS provider '" + ip + "'.");
            }
        }
    }
    
    public static void setSecondaryProviderDNS(String ip) {
        if (ip != null && ip.length() > 0) {
            if (isValidIP(ip)) {
                Server.DNS_PROVIDER_SECONDARY = Subnet.normalizeIP(ip);
                Server.logInfo("using " + ip + " as fixed secondary DNS provider.");
            } else {
                Server.logError("invalid secondary DNS provider '" + ip + "'.");
            }
        }
    }
    
    /**
     * Consulta comum no WHOIS.
     * Controla a taxa de 30 consultas no intervalo de 5 minutos.
     * @param query a consulta a ser realizada.
     * @param server o servidor que contém a informação.
     * @return o resultado do WHOIS para a consulta.
     * @throws ProcessException se houver falha no processamento da informação.
     */
    public static String whois(String query, String server) throws ProcessException {
        if (WHOIS_BR == null) {
            return null;
        } else if (WHOIS_BR.length() == 0) {
            return null;
        } else {
            long time = System.currentTimeMillis();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            try {
                if (WHOIS_CONNECTION_SEMAPHORE.tryAcquire()) {
                    try {
                        acquireWhoisQuery();
                        WhoisClient whoisClient = new WhoisClient();
                        try {
                            whoisClient.setDefaultTimeout(3000);
                            whoisClient.connect(server);
                            try (InputStream inputStream = whoisClient.getInputStream(query)) {
                                int code;
                                while ((code = inputStream.read()) != -1) {
                                    outputStream.write(code);
                                }
                            }
                        } finally {
                            whoisClient.disconnect();
                        }
                    } finally {
                        WHOIS_CONNECTION_SEMAPHORE.release();
                    }
                } else {
                    throw new ProcessException("TOO MANY CONNECTIONS");
                }
            } catch (ProcessException ex) {
                throw ex;
            } catch (Exception ex) {
                throw new ProcessException("WHOIS CONNECTION FAIL", ex);
            } 
            try {
                String result = outputStream.toString("ISO-8859-1");
                result = result.replace("\r", "");
                logWhois(time, server, query, result);
                return result;
            } catch (UnsupportedEncodingException ex) {
                throw new ProcessException("ERROR: ENCODING", ex);
            }
        }
    }
    
    /**
     * Processa a consulta e retorna o resultado.
     * @param query a expressão da consulta.
     * @return o resultado do processamento.
     */
    protected String processWHOIS(String query) {
        try {
            String result = "";
            if (query.length() == 0) {
                result = "INVALID QUERY\n";
            } else {
                StringTokenizer tokenizer = new StringTokenizer(query, " ");
                String token = tokenizer.nextToken();
                boolean updated = false;
                if (token.equals("UPDATED")) {
                    token = tokenizer.nextToken();
                    updated = true;
                }
                if (Owner.isOwnerID(token) && tokenizer.hasMoreTokens()) {
                    Owner owner = Owner.getOwner(token);
                    if (owner != null) {
                        while (tokenizer.hasMoreTokens()) {
                            String key = tokenizer.nextToken();
                            String value = owner.get(key, updated);
                            if (value == null) {
                                result += '\n';
                            } else {
                                result += value + '\n';
                            }
                        }
                    }
                } else if (isValidIP(token) && tokenizer.hasMoreTokens()) {
                    Subnet subnet = Subnet.getSubnet(token);
                    while (tokenizer.hasMoreTokens()) {
                        String field = tokenizer.nextToken();
                        String value = subnet.get(field, updated);
                        if (value == null) {
                            result += "\n";
                        } else {
                            result += value + "\n";
                        }
                    }
                } else if (Domain.containsDomain(token) && tokenizer.hasMoreTokens()) {
                    Domain domain = Domain.getDomain(token);
                    if (domain == null) {
                        result = "NOT FOUND\n";
                    } else {
                        while (tokenizer.hasMoreTokens()) {
                            String key = tokenizer.nextToken();
                            String value = domain.get(key, updated);
                            if (value == null) {
                                result += '\n';
                            } else {
                                result += value + '\n';
                            }
                        }
                    }
                } else {
                    result = "INVALID QUERY\n";
                }
            }
            return result;
        } catch (ProcessException ex) {
            Server.logError(ex.getCause());
            return ex.getMessage() + "\n";
         } catch (Exception ex) {
            Server.logError(ex);
            return "ERROR: FATAL\n";
        }
    }
    
}
