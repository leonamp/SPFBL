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

import net.spfbl.data.Provider;
import net.spfbl.data.NoReply;
import net.spfbl.data.Block;
import net.spfbl.data.White;
import net.spfbl.data.Trap;
import net.spfbl.data.Ignore;
import net.spfbl.spf.SPF;
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
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
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
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import net.spfbl.data.Generic;
import net.spfbl.dns.QueryDNS;
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
        SPF.load();
        Defer.load();
        QueryDNS.load();
        User.load();
    }
    
    private static Semaphore SEMAPHORE_STORE = new Semaphore(1);
    
    private static class Store extends Thread {
        
        public Store() {
            super("BCKGROUND");
            super.setPriority(MIN_PRIORITY);
        }
        
        @Override
        public void run() {
            try {
//                User.autoUpdateDates();
                User.autoUpdateKeys();
                User.autoInductionWhite();
                User.autoInductionBlock();
                storeAll(true, true);
            } finally {
                SEMAPHORE_STORE.release();
            }
        }
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
                storeAll(false, false);
            } finally {
                SEMAPHORE_STORE.release();
            }
        } catch (Exception ex) {
            Server.logError(ex);
        }
    }
    
    private static void storeAll(boolean simplify, boolean clone) {
        System.gc();
        Client.store();
        User.store();
        Peer.store();
        Provider.store();
        Ignore.store();
        Generic.store();
        Trap.store();
        NoReply.store();
        QueryDNS.store();
        White.store(simplify);
        Analise.store();
        Reverse.store();
        Defer.store();
        SPF.store(clone);
        Owner.store();
        Domain.store();
        AutonomousSystem.store();
        SubnetIPv4.store();
        SubnetIPv6.store();
        Handle.store();
        NameServer.store();
        Core.store();
        Block.store(simplify);
        System.gc();
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
                return new String(Base64Coder.encode(code));
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
                return Core.BASE64.encodeAsString(code);
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
                byte[] message = cipher.doFinal(Base64Coder.decode(code));
                return new String(message, "UTF8");
            } catch (Exception ex) {
                throw new ProcessException("ERROR: DECRYPTION", ex);
            }
        }
    }
    
    public static boolean isValidTicket(String code) {
        if (code == null) {
            return false;
        } else {
            try {
                decryptToByteArrayURLSafe(code);
                return true;
            } catch (ProcessException ex) {
                return false;
            }
        }
    }
    
    public static byte[] decryptToByteArrayURLSafe(String code) throws ProcessException {
        if (code == null) {
            return null;
        } else {
            try {
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
                return cipher.doFinal(Core.BASE64.decode(code));
            } catch (Exception ex) {
                throw new ProcessException("ERROR: DECRYPTION", ex);
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
                return cipher.doFinal(Base64Coder.decode(code));
            } catch (Exception ex) {
                throw new ProcessException("ERROR: DECRYPTION", ex);
            }
        }
    }
    
    private static final SimpleDateFormat FORMAT_DATE = new SimpleDateFormat("yyyy-MM-dd");
    
    /**
     * Constante de formatação da data no log.
     * Padrão ISO 8601
     * 
     * Um objeto SimpleDateFormat não é thread safety,
     * portanto é necessário utilizar sincronismo
     * nos métodos que o utilizam.
     */
    private static final SimpleDateFormat FORMAT_DATE_LOG = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
    
    /**
     * Constante de formatação da data no ticket.
     * Baseado no padrão ISO 8601
     * 
     * Um objeto SimpleDateFormat não é thread safety,
     * portanto é necessário utilizar sincronismo
     * nos métodos que o utilizam.
     */
    private static final SimpleDateFormat FORMAT_DATE_TICKET = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSSZ");
    
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
    
    public static synchronized String formatTicketDate(long time) {
        return FORMAT_DATE_TICKET.format(new Date(time));
    }
    
    public static synchronized String formatTicketDate(Date date) {
        return FORMAT_DATE_TICKET.format(date);
    }
    
    public static synchronized Date parseTicketDate(String value) throws ParseException {
        return FORMAT_DATE_TICKET.parse(value);
    }
    
    /**
     * Constante que representa a quantidade de tempo de um dia em milisegundos.
     */
    public static final long HOUR_TIME = 1000L * 60L * 60L;
    
    /**
     * Constante que representa a quantidade de tempo de um dia em milisegundos.
     */
    public static final long DAY_TIME = HOUR_TIME * 24L;
        
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
    public static void log(long time, Core.Level level, String type, String message, String result) {
        if (level.ordinal() <= Core.LOG_LEVEL.ordinal()) {
            int latencia = (int) (System.currentTimeMillis() - time);
            if (latencia > 99999) {
                // Para manter a formatação correta no LOG,
                // Registrar apenas latências até 99999, que tem 5 digitos.
                latencia = 99999;
            } else if (latencia < 0) {
                latencia = 0;
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
            Date date = new Date(time);
            String text = FORMAT_DATE_LOG.format(date)
                    + " " + LATENCIA_FORMAT.format(latencia)
                    + " " + Thread.currentThread().getName()
                    + " " + type + " " + message
                    + (result == null ? "" : " => " + result);
            PrintWriter writer = getLogWriter(date);
            if (writer == null) {
                System.out.println(text);
            } else {
                writer.println(text);
            }
        }
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
    
    private static File logFolder = null;
    private static File logFile = null;
    private static PrintWriter logWriter = null;
    private static SyslogIF syslog = null;
    private static short logExpires = 7;
    
    public static synchronized void setSyslog(Properties properties) {
//            String protocol,
//            String hostname,
//            String port
//    ) {
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
                } else if (Domain.isHostname(hostname)) {
                    hostname = Domain.extractHost(hostname, false);
                } else if (Subnet.isValidIP(hostname)) {
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
            Server.logFolder = null;
        } else {
            File folder = new File(path);
            if (folder.exists()) {
                if (folder.isDirectory()) {
                    Server.logFolder = folder;
                } else {
                    Server.logError("'" + path + "' is not a folder.");
                }
            } else {
                Server.logError("folder '" + path + "' not exists.");
            }
        }
    }
    
    public static synchronized void setLogExpires(String expires) {
        if (expires != null && expires.length() > 0) {
            try {
                setLogExpires(Integer.parseInt(expires));
            } catch (Exception ex) {
                setLogExpires(-1);
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
    
    private static synchronized PrintWriter getLogWriter(Date date) {
        try {
            if (logFolder == null || !logFolder.exists()) {
                return null;
            } else if (logWriter == null) {
                logFile = new File(logFolder, "spfbl." + FORMAT_DATE.format(date) + ".log");
                FileWriter fileWriter = new FileWriter(logFile, true);
                return logWriter = new PrintWriter(fileWriter, true);
            } else if (logFile.getName().equals("spfbl." + FORMAT_DATE.format(date) + ".log")) {
                return logWriter;
            } else {
                logWriter.close();
                logFile = new File(logFolder, "spfbl." + FORMAT_DATE.format(date) + ".log");
                FileWriter fileWriter = new FileWriter(logFile, true);
                return logWriter = new PrintWriter(fileWriter, true);
            }
        } catch (Exception ex) {
            return null;
        }
    }
    
    private static final FilenameFilter logFilter = new FilenameFilter() {
        @Override
        public boolean accept(File dir, String name) {
            return name.startsWith("spfbl.") && name.endsWith(".log");
        }
    };
    
    public static synchronized void deleteLogExpired() {
        if (logFolder != null && logFolder.exists()) {
            for (File logFileLocal : logFolder.listFiles(logFilter)) {
                long lastModified = logFileLocal.lastModified();
                long period = System.currentTimeMillis() - lastModified;
                int days = (int) (period / (1000 * 60 * 60 * 24));
                if (days > logExpires) {
                    if (logFileLocal.delete()) {
                        Server.logDebug("LOG '" + logFileLocal.getName() + "' deleted.");
                    } else {
                        Server.logDebug("LOG '" + logFileLocal.getName() + "' not deleted.");
                    }
                }
            }
        }
    }
    
    /**
     * O campo de latência do LOG tem apenas 4 digitos.
     * Serve para mostrar quais processamentos levam mais tempo
     * e para encontrar com mais facilidade códigos
     * do programa que não estão bem escritos.
     */
    private static final DecimalFormat LATENCIA_FORMAT = new DecimalFormat("00000");
    
    private static void log(
            long time,
            Core.Level level,
            String type,
            Throwable ex
    ) {
        if (ex != null) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PrintStream printStream = new PrintStream(baos);
            ex.printStackTrace(printStream);
            printStream.close();
            log(time, level, type, baos.toString(), (String) null);
        }
    }
    
    /**
     * Registra as mensagens para informação.
     * @param message a mensagem a ser registrada.
     */
    public static void logInfo(String message) {
        log(System.currentTimeMillis(), Core.Level.INFO, "INFOR", message, (String) null);
    }
    
    /**
     * Registra as mensagens para depuração.
     * @param message a mensagem a ser registrada.
     */
    public static void logDebug(String message) {
        log(System.currentTimeMillis(), Core.Level.DEBUG, "DEBUG", message, (String) null);
    }
    
    public static void logAcme(String message) {
        log(System.currentTimeMillis(), Core.Level.DEBUG, "ACMEP", message, (String) null);
    }
    
    public static void logSendMTP(String message) {
        log(System.currentTimeMillis(), Core.Level.DEBUG, "SMTPS", message, (String) null);
    }
    
    /**
     * Registra as mensagens para depuração de código.
     * @param message a mensagem a ser registrada.
     */
    public static void logTrace(String message) {
        log(System.currentTimeMillis(), Core.Level.TRACE, "TRACE", message, (String) null);
    }
    
    /**
     * Registra as mensagens de manipulação do banco de dados.
     * @param message a mensagem a ser registrada.
     */
    public static void logMySQL(String message) {
        log(System.currentTimeMillis(), Core.Level.DEBUG, "MYSQL", message, (String) null);
    }
    
    /**
     * Registra as mensagens de manipulação do banco de dados.
     * @param message a mensagem a ser registrada.
     */
    public static void logMySQL(long time, String message) {
        log(time, Core.Level.DEBUG, "MYSQL", message, null);
    }
    
    /**
     * Registra as mensagens de manipulação do banco de dados.
     * @param message a mensagem a ser registrada.
     */
    public static void logMySQL(long time, String message, String result) {
        log(time, Core.Level.DEBUG, "MYSQL", message, result);
    }
    
    /**
     * Registra as mensagens de manipulação do banco de dados.
     * @param message a mensagem a ser registrada.
     */
    public static void logMySQL(long time, String message, SQLException ex) {
        String result = "ERROR " + ex.getErrorCode() + " " + ex.getMessage();
        log(time, Core.Level.DEBUG, "MYSQL", message, result);
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
        log(time, Core.Level.DEBUG, "MYSQL", message, result);
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
        log(time, Core.Level.DEBUG, "MYSQL", message, result);
    }
    
    /**
     * Registra as gravações de cache em disco.
     * @param file o arquivo armazenado.
     */
    public static void logStore(long time, File file) {
        log(time, Core.Level.INFO, "STORE", file.getName(), (String) null);
    }
    
    /**
     * Registra os carregamentos de cache no disco.
     * @param file o arquivo carregado.
     */
    public static void logLoad(long time, File file) {
        log(time, Core.Level.INFO, "LOADC", file.getName(), (String) null);
    }
    
    /**
     * Registra as mensagens de checagem DNS.
     * @param host o host que foi consultado.
     */
    public static void logCheckDNS(
            long time, String host, String result) {
        log(time, Core.Level.DEBUG, "DNSCK", host, result);
    }
    
    /**
     * Registra os tiquetes processados.
     * @param tokenSet o conjunto de tokens.
     */
    public static void logTicket(long time, 
            TreeSet<String> tokenSet, String ticket) {
        log(time, Core.Level.DEBUG, "TIKET", tokenSet.toString(), ticket);
    }
    
    public static void logPeerSend(long time,
            String address, String token, String result) {
        log(time, Core.Level.DEBUG, "PEERS", address, token, result);
    }
    
    /**
     * Registra as consultas DNS.
     */
    public static void logLookupDNS(long time, 
            String type, String host, String result) {
        log(time, Core.Level.DEBUG, "DNSLK", type + " " + host, result);
    }
    
    /**
     * Registra as consultas DNS para HELO.
     */
    public static void logLookupHELO(long time, 
            String host, String result) {
        log(time, Core.Level.DEBUG, "HELOL", host, result);
    }
    
    /**
     * Registra as consultas de mecanismo A de SPF.
     */
    public static void logMecanismA(long time, 
            String host, String result) {
        log(time, Core.Level.DEBUG, "SPFMA", host, result);
    }
    
    /**
     * Registra as consultas de mecanismo exists de SPF.
     */
    public static void logMecanismExists(long time, 
            String host, String result) {
        log(time, Core.Level.DEBUG, "SPFEX", host, result);
    }
    
    /**
     * Registra as consultas de mecanismo MX de SPF.
     */
    public static void logMecanismMX(long time, 
            String host, String result) {
        log(time, Core.Level.DEBUG, "SPFMX", host, result);
    }
    
    /**
     * Registra verificações de macth de HELO.
     */
    public static void logMatchHELO(long time, 
            String query, String result) {
        log(time, Core.Level.DEBUG, "HELOM", query, result);
    }
    
    /**
     * Registra interações de atrazo programado.
     */
    public static void logDefer(long time, 
            String id, String result) {
        log(time, Core.Level.DEBUG, "DEFER", id, result);
    }
    
    /**
     * Registra verificações de DNS reverso.
     */
    public static void logReverseDNS(long time, 
            String ip, String result) {
        log(time, Core.Level.DEBUG, "DNSRV", ip, result);
    }
    
    /**
     * Registra as mensagens de erro.
     * @param message a mensagem a ser registrada.
     */
    public static void logError(String message) {
        log(System.currentTimeMillis(), Core.Level.ERROR, "ERROR", message, (String) null);
    }
    
    /**
     * Registra as mensagens de erro.
     * Uma iniciativa para formalização das mensagens de log.
     * @param ex a exceção a ser registrada.
     */
    public static void logError(Throwable ex) {
        log(System.currentTimeMillis(), Core.Level.ERROR, "ERROR", ex);
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
        log(time, Core.Level.DEBUG, "SPFLK", hostname, result);
    }
    
    public static void logQueryP2PUDP(long time,
            InetAddress ipAddress, String query, String result) {
        logQuery(time, "P2PUDP", ipAddress, query, result);
    }
    
    /**
     * Registra as consultas ao DNSBL do host.
     * Uma iniciativa para formalização das mensagens de log.
     * @param query a expressão da consulta.
     * @param result o resultado a ser registrado.
     */
    public static void logQueryDNSBL(long time,
            InetAddress ipAddress, String query, String result) {
        logQuery(time, "DNSBL", ipAddress, query, result);
    }
    
    public static void logQueryDNSBL(long time,
            String address, String query, String result) {
        logQuery(time, "DNSBL", address, query, result);
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
        log(time, Core.Level.DEBUG, "WHOIS", server + " " + query, result);
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
            String query, String result) {
        String origin = Client.getOrigin(ipAddress, "DNSBL");
        if (query == null) {
            log(time, Core.Level.INFO, type, origin + ":", result);
        } else {
            log(time, Core.Level.INFO, type, origin + ": " + query, result);
        }
    }
    
    public static void logQuery(
            long time,
            String type,
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
        log(time, Core.Level.INFO, type, (client == null ? "" : client + ": ") + message, null);
    }
    
    public static void log(
            long time,
            Core.Level level,
            String type,
            String client,
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
        log(time, level, type, client, query, result);
    }
    
    public static void log(
            long time,
            Core.Level level,
            String type,
            String client,
            String query,
            String result
    ) {
        log(time, level, type, (client == null ? "" : client + ": ") + query, result);
    }
    
    public static void logQuery(
            long time,
            String type,
            String client,
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
        log(time, Core.Level.INFO, type, (client == null ? "" : client + ": ") + query, result);
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
        log(time, Core.Level.INFO, "ADMIN", origin + ": " + command, result);
    }
    
    /**
     * Desliga todos os servidores instanciados.
     * @throws Exception se houver falha no fechamento de algum servidor.
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
        WHOIS_SEMAPHORE_TIMER.cancel();
        // Finaliza timer SPF.
        Core.cancelTimer();
        // Armazena os registros em disco.
        storeCache();
        // Fecha pooler de conexão MySQL.
        Core.closeConnectionPooler();
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
    private static final Timer WHOIS_SEMAPHORE_TIMER = new Timer("TIMEWHOIS");
    
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
        WHOIS_SEMAPHORE_TIMER.schedule(whoisSemaphore, WHOIS_FREQUENCY);
        WHOIS_SEMAPHORE_TIMER.purge(); // Libera referências processadas.
    }
    
    /**
     * Remove o direito a uma consulta comum no WHOIS por um dia.
     * As vezes a consulta WHOIS restringe as consultas.
     * Este método é uma forma de reduzir drasticamente a frequência.
     * @throws ProcessException se houver falha no processo.
     */
    public static void removeWhoisQueryDay() throws ProcessException {
        WhoisSemaphore whoisSemaphore = new WhoisSemaphore();
        WHOIS_SEMAPHORE_TIMER.schedule(whoisSemaphore, DAY_TIME);
    }
    
    /**
     * Remove o direito a uma consulta comum no WHOIS por uma hora.
     * As vezes a consulta WHOIS restringe as consultas.
     * Este método é uma forma de reduzir drasticamente a frequência.
     * @throws ProcessException se houver falha no processo.
     */
    public static void removeWhoisQueryHour() throws ProcessException {
        WhoisSemaphore whoisSemaphore = new WhoisSemaphore();
        WHOIS_SEMAPHORE_TIMER.schedule(whoisSemaphore, HOUR_TIME);
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
        WHOIS_SEMAPHORE_TIMER.schedule(whoisIDSemaphore, DAY_TIME); // Libera o direito à consulta em 24h.
        WHOIS_SEMAPHORE_TIMER.purge(); // Libera referências processadas.
    }
    
    /**
     * Semáphoro que controla o número máximo de conexões simutâneas no WHOIS.
     * Limite de 2 conexões simultâneas por IP de origem.
     */
    private static final Semaphore WHOIS_CONNECTION_SEMAPHORE = new Semaphore(2);
    
    /**
     * Consulta de identificação no WHOIS.
     * Controla a taxa de 30 consultas no intervalo de 24 horas.
     * @param query a consulta a ser realizada.
     * @param server o servidor que contém a informação.
     * @return o resultado do WHOIS para a consulta.
     * @throws ProcessException se houver falha no processamento da informação.
     */
    public static String whoisID(String query, String server) throws ProcessException {
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
    
    /**
     * Constante do servidor WHOIS brasileiro.
     */
    public static final String WHOIS_BR = "whois.nic.br";
    
    /**
     * Consulta de registros de nome de domínio.
     */
    private static InitialDirContext INITIAL_DIR_CONTEXT;
    
    public static Attributes getAttributesDNS(String hostname, String[] types) throws NamingException {
        return INITIAL_DIR_CONTEXT.getAttributes("dns:/" + hostname, types);
    }
    
    static {
        try {
            initDNS();
        } catch (Exception ex) {
            Server.logError(ex);
            System.exit(1);
        }
    }
    
    private static String DNS_PROVIDER = null;
    
    public static void setProviderDNS(String ip) {
        if (ip != null && ip.length() > 0) {
            if (Subnet.isValidIP(ip)) {
                Server.DNS_PROVIDER = Subnet.normalizeIP(ip);
                Server.logInfo("using " + ip + " as fixed DNS provider.");
            } else {
                Server.logError("invalid DNS provider '" + ip + "'.");
            }
        }
    }
    
    @SuppressWarnings("unchecked")
    public static void initDNS() throws NamingException {
        Hashtable env = new Hashtable();
        env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
        env.put("com.sun.jndi.dns.timeout.initial", "3000");
        env.put("com.sun.jndi.dns.timeout.retries", "1");
        if (DNS_PROVIDER != null) {
            env.put("java.naming.provider.url", "dns://" + DNS_PROVIDER);
        }
        INITIAL_DIR_CONTEXT = new InitialDirContext(env);
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
    
    /**
     * Atualiza os registros quase expirando.
     */
    public static synchronized boolean tryRefreshWHOIS() {
        if (WHOIS_QUERY_SEMAPHORE.availablePermits() == WHOIS_QUERY_LIMIT) {
            if (Domain.backgroundRefresh()) {
                return true;
            } else {
                return Subnet.backgroundRefresh();
            }
        } else {
            return false;
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
                } else if (Subnet.isValidIP(token) && tokenizer.hasMoreTokens()) {
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
