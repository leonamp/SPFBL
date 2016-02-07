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
import net.spfbl.spf.SPF.Distribution;
import net.spfbl.spf.SPF.Status;
import net.spfbl.whois.AutonomousSystem;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Handle;
import net.spfbl.whois.NameServer;
import net.spfbl.whois.Owner;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv4;
import net.spfbl.whois.SubnetIPv6;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.Timer;
import java.util.TimerTask;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import net.spfbl.dnsbl.QueryDNSBL;
import net.spfbl.dnsbl.ServerDNSBL;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.commons.net.whois.WhoisClient;

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
    private static final LinkedList<Server> SERVER_LIST = new LinkedList<Server>();
    
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
        User.load();
        Owner.load();
        Domain.load();
        AutonomousSystem.load();
        SubnetIPv4.load();
        SubnetIPv6.load();
        Handle.load();
        NameServer.load();
        Peer.load();
        Reverse.load();
        SPF.load();
        NoReply.load();
        Defer.load();
        QueryDNSBL.load();
    }
    
    /**
     * Armazenamento de cache em disco.
     */
    public static void storeCache() {
        Client.store();
        User.store();
        Owner.store();
        Domain.store();
        AutonomousSystem.store();
        SubnetIPv4.store();
        SubnetIPv6.store();
        Handle.store();
        NameServer.store();
        Peer.store();
        Reverse.store();
        SPF.store();
        NoReply.store();
        Defer.store();
        QueryDNSBL.store();
    }
    
    private static SecretKey privateKey = null;
    
    private static SecretKey getPrivateKey() {
        if (privateKey == null) {
            try {
                File file = new File("./data/server.key");
                if (file.exists()) {
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        privateKey = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                } else {
                    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                    keyGen.init(new SecureRandom());
                    SecretKey key = keyGen.generateKey();
                    FileOutputStream outputStream = new FileOutputStream(file);
                    try {
                        SerializationUtils.serialize(key, outputStream);
                    } finally {
                        outputStream.close();
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
    private static final SimpleDateFormat FORMAT_DATE_LOG = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSSZ");
    
    /**
     * Constante de formatação da data no ticket.
     * Baseado no padrão ISO 8601
     * 
     * Um objeto SimpleDateFormat não é thread safety,
     * portanto é necessário utilizar sincronismo
     * nos métodos que o utilizam.
     */
    private static final SimpleDateFormat FORMAT_DATE_TICKET = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSSZ");
    
    private static long LAST_TICKET_TIME = 0;
    
    public static synchronized String getNewTicketDate() {
        long time = System.currentTimeMillis();
        if (time <= LAST_TICKET_TIME) {
            // Não permite criar dois tickets 
            // exatamente com a mesma data para 
            // que o hash fique sempre diferente.
            time = LAST_TICKET_TIME + 1;
        }
        LAST_TICKET_TIME = time;
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
    public static final int HOUR_TIME = 1000 * 60 * 60;
    
    /**
     * Constante que representa a quantidade de tempo de um dia em milisegundos.
     */
    public static final int DAY_TIME = HOUR_TIME * 24;
        
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
            }
            if (result != null) {
                result = result.replace("\r", "\\r");
                result = result.replace("\n", "\\n");
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
    }
    
    private static File logFolder = null;
    private static File logFile = null;
    private static PrintWriter logWriter = null;
    private static short logExpires = 7;
    
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
            Server.logError("invalid expires integer value '" + expires + "'.");
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
            Throwable ex) {
        if (ex != null) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PrintStream printStream = new PrintStream(baos);
            ex.printStackTrace(printStream);
            printStream.close();
            log(time, level, type, baos.toString(), (String) null);
        }
    }
    
    public static void logBlockTrace(long time, String message) {
        log(time, Core.Level.TRACE, "BLOCK", message, (String) null);
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
    
    /**
     * Registra as mensagens para depuração de código.
     * @param message a mensagem a ser registrada.
     */
    public static void logTrace(String message) {
        log(System.currentTimeMillis(), Core.Level.TRACE, "TRACE", message, (String) null);
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
        if (ex instanceof ProcessException) {
            ProcessException pex = (ProcessException) ex;
            log(System.currentTimeMillis(), Core.Level.ERROR, "ERROR", pex.getErrorMessage(), (String) null);
        } else if (ex instanceof Exception) {
            log(System.currentTimeMillis(), Core.Level.ERROR, "ERROR", ex);
        }
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
     * @param time o tempo de processamento da consulta.
     * @param query a expressão da consulta.
     * @param result a expressão do resultado.
     */
    public static void logQuery(
            long time,
            String type,
            InetAddress ipAddress,
            String query, String result) {
        String origin = Client.getOrigin(ipAddress);
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
            String query, String result) {
        log(time, level, type, (client == null ? "" : client + ": ") + query, result);
    }
    
    public static void logQuery(
            long time,
            String type,
            String client,
            String query, String result) {
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
        String origin = Client.getOrigin(ipAddress);
        log(time, Core.Level.INFO, "ADMIN", origin + ": " + command, result);
    }
    
    /**
     * Desliga todos os servidores instanciados.
     * @throws Exception se houver falha no fechamento de algum servidor.
     */
    public static boolean shutdown() {
        // Inicia finalização dos servidores.
        Server.logInfo("shutting down server...");
        boolean closed = true;
        for (Server server : SERVER_LIST) {
            try {
                server.run = false;
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
//            WHOIS_CONNECTION_SEMAPHORE.acquire();
            if (WHOIS_CONNECTION_SEMAPHORE.tryAcquire(3, TimeUnit.SECONDS)) {
                try {
                    acquireWhoisIDQuery();
                    WhoisClient whoisClient = new WhoisClient();
                    try {
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
                throw new ProcessException("ERROR: TOO MANY CONNECTIONS");
            }
        } catch (ProcessException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new ProcessException("ERROR: WHOIS CONNECTION FAIL", ex);
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
    
    @SuppressWarnings("unchecked")
    public static void initDNS() throws NamingException {
        Hashtable env = new Hashtable();
        env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
        env.put("com.sun.jndi.dns.timeout.initial", "3000");
        env.put("com.sun.jndi.dns.timeout.retries", "1");
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
//            WHOIS_CONNECTION_SEMAPHORE.acquire();
            if (WHOIS_CONNECTION_SEMAPHORE.tryAcquire(3, TimeUnit.SECONDS)) {
                try {
                    acquireWhoisQuery();
                    WhoisClient whoisClient = new WhoisClient();
                    try {
                        whoisClient.connect(server);
                        InputStream inputStream = whoisClient.getInputStream(query);
                        try {
                            int code;
                            while ((code = inputStream.read()) != -1) {
                                outputStream.write(code);
                            }
                        } finally {
                            inputStream.close();
                        }
                    } finally {
                        whoisClient.disconnect();
                    }
                } finally {
                    WHOIS_CONNECTION_SEMAPHORE.release();
                }
            } else {
                throw new ProcessException("ERROR: TOO MANY CONNECTIONS");
            }
        } catch (ProcessException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new ProcessException("ERROR: WHOIS CONNECTION FAIL", ex);
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
    
    public static synchronized void tryRefreshWHOIS() {
        // Evita que muitos processos fiquem 
        // presos aguardando a liberação do método.
        if (WHOIS_QUERY_SEMAPHORE.availablePermits() == WHOIS_QUERY_LIMIT) {
            refreshWHOIS();
        }
    }
    
    /**
     * Atualiza os registros quase expirando.
     */
    public static synchronized boolean refreshWHOIS() {
        if (WHOIS_QUERY_SEMAPHORE.availablePermits() == WHOIS_QUERY_LIMIT) {
            if (Domain.backgroundRefresh()) {
                return true;
            } else if (Subnet.backgroundRefresh()) {
                return true;
            } else {
                return false;
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
                result = "ERROR: QUERY\n";
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
                    while (tokenizer.hasMoreTokens()) {
                        String key = tokenizer.nextToken();
                        String value = owner.get(key, updated);
                        if (value == null) {
                            result += '\n';
                        } else {
                            result += value + '\n';
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
                    while (tokenizer.hasMoreTokens()) {
                        String key = tokenizer.nextToken();
                        String value = domain.get(key, updated);
                        if (value == null) {
                            result += '\n';
                        } else {
                            result += value + '\n';
                        }
                    }
                } else {
                    result = "ERROR: QUERY\n";
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
    
    public static final DecimalFormat CENTENA_FORMAT = new DecimalFormat("000");
    
    public static final NumberFormat DECIMAL_FORMAT = NumberFormat.getNumberInstance();
    
    /**
     * Processa o comando e retorna o resultado.
     * @param command a expressão do comando.
     * @return o resultado do processamento.
     */
    protected String processCommand(String command) {
        try {
            String result = "";
            if (command.length() == 0) {
                result = "ERROR: COMMAND\n";
            } else {
                StringTokenizer tokenizer = new StringTokenizer(command, " ");
                String token = tokenizer.nextToken();
                if (token.equals("VERSION") && !tokenizer.hasMoreTokens()) {
                    return Core.getAplication() + "\n";
                } else if (token.equals("DUMP") && !tokenizer.hasMoreTokens()) {
                    StringBuilder builder = new StringBuilder();
                    builder.append("BLOCK DROP ALL\n");
                    for (String block : SPF.getAllBlockSet()) {
                        builder.append("BLOCK ADD ");
                        builder.append(block);
                        builder.append('\n');
                    }
                    builder.append("CLIENT DROP ALL\n");
                    for (Client client : Client.getSet()) {
                        builder.append("CLIENT ADD ");
                        builder.append(client.getCIDR());
                        builder.append(' ');
                        builder.append(client.getDomain());
                        builder.append(' ');
                        builder.append(client.getPermission().name());
                        if (client.hasEmail()) {
                            builder.append(' ');
                            builder.append(client.getEmail());
                        }
                        builder.append('\n');
                    }
                    builder.append("DNSBL DROP ALL\n");
                    for (ServerDNSBL server : QueryDNSBL.getValues()) {
                        builder.append("DNSBL ADD ");
                        builder.append(server.getHostName());
                        builder.append(' ');
                        builder.append(server.getMessage());
                        builder.append('\n');
                    }
                    builder.append("GUESS DROP ALL\n");
                    HashMap<String,String> guessMap = SPF.getGuessMap();
                    for (String domain : guessMap.keySet()) {
                        String guess = guessMap.get(domain);
                        builder.append("GUESS ADD ");
                        builder.append(domain);
                        builder.append(" \"");
                        builder.append(guess);
                        builder.append("\"\n");
                    }
                    builder.append("IGNORE DROP ALL\n");
                    for (String ignore : SPF.getIgnoreSet()) {
                        builder.append("IGNORE ADD ");
                        builder.append(ignore);
                        builder.append('\n');
                    }
                    builder.append("PEER DROP ALL\n");
                    for (Peer peer : Peer.getSet()) {
                        builder.append("PEER ADD ");
                        builder.append(peer.getAddress());
                        builder.append(':');
                        builder.append(peer.getPort());
                        builder.append(' ');
                        builder.append(peer.getSendStatus().name());
                        builder.append(' ');
                        builder.append(peer.getReceiveStatus().name());
                        if (peer.hasEmail()) {
                            builder.append(' ');
                            builder.append(peer.getEmail());
                        }
                        builder.append('\n');
                    }
                    builder.append("PROVIDER DROP ALL\n");
                    for (String provider : SPF.getProviderSet()) {
                        builder.append("PROVIDER ADD ");
                        builder.append(provider);
                        builder.append('\n');
                    }
                    builder.append("TLD DROP ALL\n");
                    for (String tld : Domain.getTLDSet()) {
                        builder.append("TLD ADD ");
                        builder.append(tld);
                        builder.append('\n');
                    }
                    builder.append("TRAP DROP ALL\n");
                    for (String trap : SPF.getAllTrapSet()) {
                        builder.append("TRAP ADD ");
                        builder.append(trap);
                        builder.append('\n');
                    }
                    builder.append("USER DROP ALL\n");
                    for (User user : User.getSet()) {
                        builder.append("USER ADD ");
                        builder.append(user.getEmail());
                        builder.append(' ');
                        builder.append(user.getName());
                        builder.append('\n');
                    }
                    builder.append("WHITE DROP ALL\n");
                    for (String white : SPF.getAllWhiteSet()) {
                        builder.append("WHITE ADD ");
                        builder.append(white);
                        builder.append('\n');
                    }
                    builder.append("STORE\n");
                    result = builder.toString();
                } else if (token.equals("SPLIT") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (Subnet.isValidCIDR(token)) {
                            String cidr = token;
                            if (SPF.dropBlock(cidr)) {
                                result += "DROPED " + cidr + "\n";
                                result += splitCIDR(cidr);
                            } else {
                                result = "NOT FOUND\n";
                            }
                            SPF.storeBlock();
                        } else {
                            result = "ERROR: COMMAND\n";
                        }
                } else if (token.equals("LOG") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("LEVEL") && tokenizer.countTokens() == 1) {
                        token = tokenizer.nextToken();
                        try {
                            Core.Level level = Core.Level.valueOf(token);
                            if (Core.setLevelLOG(level)) {
                                result += "CHANGED\n";
                            } else {
                                result += "SAME\n";
                            }
                        } catch (Exception ex) {
                            result = "ERROR: COMMAND\n";
                        }
                    } else {
                        result = "ERROR: COMMAND\n";
                    }
                } else if (token.equals("RELOAD") && !tokenizer.hasMoreTokens()) {
                    if (Core.loadConfiguration()) {
                        result = "RELOADED\n";
                    } else {
                        result = "FAILED\n";
                    }
                } else if (token.equals("URL") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.countTokens() == 2) {
                        String domain = tokenizer.nextToken();
                        String url = tokenizer.nextToken();
                        if (Core.addURL(domain, url)) {
                            result = "ADDED\n";
                            Core.storeURL();
                        } else {
                            result = "INVALID\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.countTokens() == 1) {
                        String domain = tokenizer.nextToken();
                        String url = Core.dropURL(domain);
                        if (url == null) {
                            result = "NOT FOUND\n";
                        } else {
                            result = "DROPED " + url + "\n";
                            Core.storeURL();
                        }
                    } else if (token.equals("SHOW") && tokenizer.countTokens() == 0) {
                        HashMap<String,String> map = Core.getMapURL();
                        for (String domain : map.keySet()) {
                            String url = map.get(domain);
                            result += domain + " " + (url == null ? "NONE" : url) + "\n";
                        }
                        if (result.length() == 0) {
                            result = "EMPTY\n";
                        }
                    } else {
                        result = "ERROR: COMMAND\n";
                    }
                } else if (token.equals("SHUTDOWN") && !tokenizer.hasMoreTokens()) {
                    // Comando para finalizar o serviço.
                    if (shutdown()) {
                        // Fechamento de processos realizado com sucesso.
                        result = "OK\n";
                    } else {
                        // Houve falha no fechamento dos processos.
                        result = "ERROR: SHUTDOWN\n";
                    }
                } else if (token.equals("STORE") && !tokenizer.hasMoreTokens()) {
                    // Comando para gravar o cache em disco.
                    result = "OK\n";
                    storeCache();
                } else if (token.equals("TLD") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.hasMoreTokens()) {
                        // Comando para adicionar TLDs.
                        while (tokenizer.hasMoreTokens()) {
                            try {
                                String tld = tokenizer.nextToken();
                                if (Domain.addTLD(tld)) {
                                    result += "ADDED\n";
                                } else {
                                    result += "ALREADY EXISTS\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            TreeSet<String> tldSet = Domain.dropAllTLD();
                            if (tldSet.isEmpty()) {
                                result = "EMPTY\n";
                            } else {
                                for (String tld : tldSet) {
                                    result += "DROPED " + tld + "\n";
                                }
                            }
                        } else {
                            try {
                                if (Domain.removeTLD(token)) {
                                    result = "DROPED\n";
                                } else {
                                    result = "NOT FOUND\n";
                                }
                            } catch (ProcessException ex) {
                                result = ex.getMessage() + "\n";
                            }
                        }
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        for (String tld : Domain.getTLDSet()) {
                            result += tld + "\n";
                        }
                        if (result.length() == 0) {
                            result = "EMPTY\n";
                        }
                    } else {
                        result = "ERROR: COMMAND\n";
                    }
                } else if (token.equals("DNSBL") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.countTokens() >= 2) {
                        String hostname = tokenizer.nextToken();
                        String message = tokenizer.nextToken();
                        while (tokenizer.hasMoreTokens()) {
                            message += ' ' + tokenizer.nextToken();
                        }
                        if (QueryDNSBL.add(hostname, message)) {
                            result = "ADDED\n";
                        } else {
                            result = "ALREADY EXISTS\n";
                        }
                        QueryDNSBL.store();
                    } else if (token.equals("SET") && tokenizer.countTokens() >= 2) {
                        String hostname = tokenizer.nextToken();
                        String message = tokenizer.nextToken();
                        while (tokenizer.hasMoreTokens()) {
                            message += ' ' + tokenizer.nextToken();
                        }
                        if (QueryDNSBL.set(hostname, message)) {
                            result = "UPDATED\n";
                        } else {
                            result = "NOT FOUND\n";
                        }
                        QueryDNSBL.store();
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        while (tokenizer.hasMoreTokens()) {
                            token = tokenizer.nextToken();
                            if (token.equals("ALL")) {
                                for (ServerDNSBL server : QueryDNSBL.dropAll()) {
                                    result += "DROPED " + server + "\n";
                                }
                            } else {
                                ServerDNSBL server = QueryDNSBL.drop(token);
                                if (server == null) {
                                    result += "NOT FOUND\n";
                                } else {
                                    result += "DROPED " + server + "\n";
                                }
                            }
                        }
                        QueryDNSBL.store();
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        HashMap<String,ServerDNSBL> map = QueryDNSBL.getMap();
                        if (map.isEmpty()) {
                            result = "EMPTY\n";
                        } else {
                            for (String key : map.keySet()) {
                                ServerDNSBL server = map.get(key);
                                result += server + " " + server.getMessage() + "\n";
                            }
                        }
                    } else {
                        result = "ERROR: COMMAND\n";
                    }
                } else if (token.equals("PROVIDER") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.hasMoreTokens()) {
                        // Comando para adicionar provedor de e-mail.
                        while (tokenizer.hasMoreTokens()) {
                            try {
                                String provider = tokenizer.nextToken();
                                if (SPF.addProvider(provider)) {
                                    result += "ADDED\n";
                                } else {
                                    result += "ALREADY EXISTS\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "ERROR: COMMAND\n";
                        }
                        SPF.storeProvider();
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            TreeSet<String> providerSet = SPF.dropAllProvider();
                            if (providerSet.isEmpty()) {
                                result = "EMPTY\n";
                            } else {
                                for (String provider : providerSet) {
                                    result += "DROPED " + provider + "\n";
                                }
                            }
                        } else {
                            try {
                                if (SPF.dropProvider(token)) {
                                    result = "DROPED\n";
                                } else {
                                    result = "NOT FOUND\n";
                                }
                            } catch (ProcessException ex) {
                                result = ex.getMessage() + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "ERROR: COMMAND\n";
                        }
                        SPF.storeProvider();
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        // Mecanismo de visualização de provedores.
                        for (String provider : SPF.getProviderSet()) {
                            result += provider + "\n";
                        }
                        if (result.length() == 0) {
                            result = "EMPTY\n";
                        }
                    } else {
                        result = "ERROR: COMMAND\n";
                    }
                } else if (token.equals("IGNORE") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.hasMoreTokens()) {
                        // Comando para adicionar provedor de e-mail.
                        while (tokenizer.hasMoreTokens()) {
                            try {
                                String ignore = tokenizer.nextToken();
                                if (SPF.addIgnore(ignore)) {
                                    result += "ADDED\n";
                                } else {
                                    result += "ALREADY EXISTS\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "ERROR: COMMAND\n";
                        }
                        SPF.storeIgnore();
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            TreeSet<String> ignoreSet = SPF.dropAllIgnore();
                            if (ignoreSet.isEmpty()) {
                                result = "EMPTY\n";
                            } else {
                                for (String ignore : ignoreSet) {
                                    result += "DROPED " + ignore + "\n";
                                }
                            }
                        } else {
                            try {
                                if (SPF.dropIgnore(token)) {
                                    result += "DROPED\n";
                                } else {
                                    result += "NOT FOUND\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "ERROR: COMMAND\n";
                        }
                        SPF.storeIgnore();
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        // Mecanismo de visualização de provedores.
                        TreeSet<String> ignoreSet = SPF.getIgnoreSet();
                        for (String ignore : ignoreSet) {
                            result += ignore + "\n";
                        }
                        if (result.length() == 0) {
                            result = "EMPTY\n";
                        }
                    } else {
                        result = "ERROR: COMMAND\n";
                    }
                } else if (token.equals("BLOCK") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.hasMoreTokens()) {
                        while (tokenizer.hasMoreElements()) {
                            try {
                                String blockedToken = tokenizer.nextToken();
                                int index = blockedToken.indexOf(':');
                                String client = null;
                                if (index != -1) {
                                    String prefix = blockedToken.substring(0, index);
                                    if (Domain.isEmail(prefix)) {
                                        client = prefix;
                                        blockedToken = blockedToken.substring(index+1);
                                    }
                                }
                                if (client == null && (blockedToken = SPF.addBlock(blockedToken)) != null) {
                                    Peer.sendBlockToAll(blockedToken);
                                    result += "ADDED\n";
                                } else if (client != null && SPF.addBlock(client, blockedToken)) {
                                    result += "ADDED\n";
                                } else {
                                    result += "ALREADY EXISTS\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "ERROR: COMMAND\n";
                        }
                        SPF.storeBlock();
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            if (tokenizer.hasMoreTokens()) {
                                result = "ERROR: COMMAND\n";
                            } else {
                                try {
                                    if (SPF.dropAllBlock()) {
                                        result += "DROPED\n";
                                    } else {
                                        result += "EMPTY\n";
                                    }
                                } catch (ProcessException ex) {
                                    result += ex.getMessage() + "\n";
                                }
                            }
                        } else {
                            do {
                                try {
                                    int index = token.indexOf(':');
                                    String client = null;
                                    if (index != -1) {
                                        String prefix = token.substring(0, index);
                                        if (Domain.isEmail(prefix)) {
                                            client = prefix;
                                            token = token.substring(index+1);
                                        }
                                    }
                                    if (client == null && SPF.dropBlock(token)) {
                                        result += "DROPED\n";
                                    } else if (client != null && SPF.dropBlock(client, token)) {
                                        result += "DROPED\n";
                                    } else {
                                        result += "NOT FOUND\n";
                                    }
                                } catch (ProcessException ex) {
                                    result += ex.getMessage() + "\n";
                                }
                            } while (tokenizer.hasMoreElements());
                            if (result.length() == 0) {
                                result = "ERROR: COMMAND\n";
                            }
                        }
                        SPF.storeBlock();
                    } else if (token.equals("SHOW")) {
                        if (!tokenizer.hasMoreTokens()) {
                            // Mecanismo de visualização 
                            // de bloqueios de remetentes.
                            for (String sender : SPF.getBlockSet()) {
                                result += sender + "\n";
                            }
                            if (result.length() == 0) {
                                result = "EMPTY\n";
                            }
                        } else if (tokenizer.countTokens() == 1) {
                            token = tokenizer.nextToken();
                            if (token.equals("ALL")) {
                                // Mecanismo de visualização de 
                                // todos os bloqueios de remetentes.
                                for (String sender : SPF.getAllBlockSet()) {
                                    result += sender + "\n";
                                }
                                if (result.length() == 0) {
                                    result = "EMPTY\n";
                                }
                            }
                        }
                    } else {
                        result = "ERROR: COMMAND\n";
                    }
                } else if (token.equals("WHITE") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.hasMoreTokens()) {
                        while (tokenizer.hasMoreElements()) {
                            try {
                                String whiteToken = tokenizer.nextToken();
                                int index = whiteToken.indexOf(':');
                                String client = null;
                                if (index != -1) {
                                    String prefix = whiteToken.substring(0, index);
                                    if (Domain.isEmail(prefix)) {
                                        client = prefix;
                                        whiteToken = whiteToken.substring(index+1);
                                    }
                                }
                                if (client == null && SPF.addWhite(whiteToken)) {
                                    result += "ADDED\n";
                                } else if (client != null && SPF.addWhite(client, whiteToken)) {
                                    result += "ADDED\n";
                                } else {
                                    result += "ALREADY EXISTS\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "ERROR: COMMAND\n";
                        }
                        SPF.storeWhite();
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            TreeSet<String> whiteSet = SPF.dropAllWhite();
                            if (whiteSet.isEmpty()) {
                                result = "EMPTY\n";
                            } else {
                                for (String white : whiteSet) {
                                    result += "DROPED " + white + "\n";
                                }
                            }
                        } else {
                            try {
                                int index = token.indexOf(':');
                                String client = null;
                                if (index != -1) {
                                    String prefix = token.substring(0, index);
                                    if (Domain.isEmail(prefix)) {
                                        client = prefix;
                                        token = token.substring(index+1);
                                    }
                                }
                                if (client == null && SPF.dropWhite(token)) {
                                    result = "DROPED\n";
                                } else if (client != null && SPF.dropWhite(client, token)) {
                                    result = "DROPED\n";
                                } else {
                                    result = "NOT FOUND\n";
                                }
                            } catch (ProcessException ex) {
                                result = ex.getMessage() + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "ERROR: COMMAND\n";
                        }
                        SPF.storeWhite();
                    } else if (token.equals("SHOW")) {
                        if (!tokenizer.hasMoreTokens()) {
                            // Mecanismo de visualização 
                            // de liberação de remetentes.
                            for (String sender : SPF.getWhiteSet()) {
                                result += sender + "\n";
                            }
                            if (result.length() == 0) {
                                result = "EMPTY\n";
                            }
                        } else if (tokenizer.countTokens() == 1) {
                            token = tokenizer.nextToken();
                            if (token.equals("ALL")) {
                                // Mecanismo de visualização de 
                                // todos os liberação de remetentes.
                                for (String sender : SPF.getAllWhiteSet()) {
                                    result += sender + "\n";
                                }
                                if (result.length() == 0) {
                                    result = "EMPTY\n";
                                }
                            }
                        }
                    } else {
                        result = "ERROR: COMMAND\n";
                    }
                } else if (token.equals("TRAP") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.hasMoreTokens()) {
                        while (tokenizer.hasMoreElements()) {
                            try {
                                String trapToken = tokenizer.nextToken();
                                int index = trapToken.indexOf(':');
                                String client = null;
                                if (index != -1) {
                                    String prefix = trapToken.substring(0, index);
                                    if (Domain.isEmail(prefix)) {
                                        client = prefix;
                                        trapToken = trapToken.substring(index+1);
                                    }
                                }
                                if (client == null && SPF.addTrap(trapToken)) {
                                    result += "ADDED\n";
                                } else if (client != null && SPF.addTrap(client, trapToken)) {
                                    result += "ADDED\n";
                                } else {
                                    result += "ALREADY EXISTS\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "ERROR: COMMAND\n";
                        }
                        SPF.storeTrap();
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            TreeSet<String> trapSet = SPF.dropAllTrap();
                            if (trapSet.isEmpty()) {
                                result = "EMPTY\n";
                            } else {
                                for (String trap : trapSet) {
                                    result += "DROPED " + trap + "\n";
                                }
                            }
                        } else {
                            try {
                                int index = token.indexOf(':');
                                String client = null;
                                if (index != -1) {
                                    String prefix = token.substring(0, index);
                                    if (Domain.isEmail(prefix)) {
                                        client = prefix;
                                        token = token.substring(index+1);
                                    }
                                }
                                if (client == null && SPF.dropTrap(token)) {
                                    result = "DROPED\n";
                                } else if (client != null && SPF.dropTrap(client, token)) {
                                    result = "DROPED\n";
                                } else {
                                    result = "NOT FOUND\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "ERROR: COMMAND\n";
                        }
                        SPF.storeTrap();
                    } else if (token.equals("SHOW")) {
                        if (!tokenizer.hasMoreTokens()) {
                            // Mecanismo de visualização 
                            // de liberação de remetentes.
                            for (String sender : SPF.getTrapSet()) {
                                result += sender + "\n";
                            }
                            if (result.length() == 0) {
                                result = "EMPTY\n";
                            }
                        } else if (tokenizer.countTokens() == 1) {
                            token = tokenizer.nextToken();
                            if (token.equals("ALL")) {
                                // Mecanismo de visualização de 
                                // todos os liberação de remetentes.
                                for (String sender : SPF.getAllTrapSet()) {
                                    result += sender + "\n";
                                }
                                if (result.length() == 0) {
                                    result = "EMPTY\n";
                                }
                            }
                        }
                    } else {
                        result = "ERROR: COMMAND\n";
                    }
                } else if (token.equals("SPLIT") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (Subnet.isValidCIDR(token)) {
                        String cidr = token;
                        if (SPF.dropBlock(cidr)) {
                            result += "DROPED " + cidr + "\n";
                            result += splitCIDR(cidr);
                        } else {
                            result = "NOT FOUND\n";
                        }
                        SPF.storeBlock();
                    } else {
                        result = "ERROR: COMMAND\n";
                    }
                } else if (token.equals("NOREPLY") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.hasMoreTokens()) {
                        while (tokenizer.hasMoreElements()) {
                            try {
                                token = tokenizer.nextToken();
                                if (NoReply.add(token)) {
                                    result += "ADDED\n";
                                } else {
                                    result += "ALREADY EXISTS\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "ERROR: COMMAND\n";
                        }
                        NoReply.store();
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            TreeSet<String> noreplaySet = NoReply.dropAll();
                            if (noreplaySet.isEmpty()) {
                                result = "EMPTY\n";
                            } else {
                                for (String noreplay : noreplaySet) {
                                    result += "DROPED " + noreplay + "\n";
                                }
                            }
                        } else {
                            try {
                                if (NoReply.drop(token)) {
                                    result = "DROPED\n";
                                } else {
                                    result = "NOT FOUND\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
                            }
                        }
                        if (result.length() == 0) {
                            result = "ERROR: COMMAND\n";
                        }
                        NoReply.store();
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        for (String sender : NoReply.getSet()) {
                            result += sender + "\n";
                        }
                        if (result.length() == 0) {
                            result = "EMPTY\n";
                        }
                    } else {
                        result = "ERROR: COMMAND\n";
                    }
                } else if (token.equals("CLIENT") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.hasMoreTokens()) {
                        String cidr = tokenizer.nextToken();
                        if (tokenizer.hasMoreTokens()) {
                            String domain = tokenizer.nextToken();
                            if (tokenizer.hasMoreTokens()) {
                                String permission = tokenizer.nextToken();
                                String email = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                                try {
                                    Client client = Client.create(
                                            cidr, domain, permission, email
                                    );
                                    if (client == null) {
                                        result = "ALREADY EXISTS\n";
                                    } else {
                                        result = "ADDED " + client + "\n";
                                    }
                                } catch (ProcessException ex) {
                                    result = ex.getMessage() + "\n";
                                }
                                Client.store();
                            } else {
                                result = "ERROR: COMMAND\n";
                            }
                        } else {
                            result = "ERROR: COMMAND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            TreeSet<Client> clientSet = Client.dropAll();
                            if (clientSet.isEmpty()) {
                                result += "EMPTY\n";
                            } else {
                                for (Client client : clientSet) {
                                    result += "DROPED " + client + "\n";
                                }
                            }
                            Client.store();
                        } else if (Subnet.isValidCIDR(token)) {
                            Client client = Client.drop(token);
                            if (client == null) {
                                result += "NOT FOUND\n";
                            } else {
                                result += "DROPED " + client + "\n";
                            }
                            Client.store();
                        } else {
                            result = "ERROR: COMMAND\n";
                        }
                        
                    } else if (token.equals("SHOW")) {
                        if (tokenizer.hasMoreTokens()) {
                            token = tokenizer.nextToken();
                            if (token.equals("DNSBL")) {
                                for (Client client : Client.getSet(Client.Permission.DNSBL)) {
                                    result += client + "\n";
                                }
                                if (result.length() == 0) {
                                    result = "EMPTY\n";
                                }
                            } else if (token.equals("SPFBL")) {
                                for (Client client : Client.getSet(Client.Permission.SPFBL)) {
                                    result += client + "\n";
                                }
                                if (result.length() == 0) {
                                    result = "EMPTY\n";
                                }
                            } else if (token.equals("NONE")) {
                                for (Client client : Client.getSet(Client.Permission.NONE)) {
                                    result += client + "\n";
                                }
                                if (result.length() == 0) {
                                    result = "EMPTY\n";
                                }
                            } else if (token.equals("ALL")) {
                                for (Client client : Client.getSet(Client.Permission.ALL)) {
                                    result += client + "\n";
                                }
                                if (result.length() == 0) {
                                    result = "EMPTY\n";
                                }
                            } else if (Subnet.isValidIP(token)) {
                                Client client = Client.getByIP(token);
                                if (client == null) {
                                    result += "NOT FOUND\n";
                                } else {
                                    result += client + "\n";
                                }
                            } else {
                                result = "ERROR: COMMAND\n";
                            }
                        } else {
                            for (Client client : Client.getSet()) {
                                result += client + "\n";
                            }
                            if (result.length() == 0) {
                                result = "EMPTY\n";
                            }
                        }
                    } else if (token.equals("SET") && tokenizer.hasMoreTokens()) {
                        String cidr = tokenizer.nextToken();
                        if (tokenizer.hasMoreTokens()) {
                            String domain = tokenizer.nextToken();
                            if (tokenizer.hasMoreTokens()) {
                                String permission = tokenizer.nextToken();
                                String email = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null;
                                if (tokenizer.hasMoreTokens()) {
                                    result = "ERROR: COMMAND\n";
                                } else if (!Domain.isHostname(domain)) {
                                    result = "ERROR: INVALID DOMAIN\n";
                                } else if (email != null && !Domain.isEmail(email)) {
                                    result = "ERROR: INVALID EMAIL\n";
                                } else {
                                    Client client = Client.getByCIDR(cidr);
                                    if (client == null) {
                                        result += "NOT FOUND\n";
                                    } else {
                                        client.setPermission(permission);
                                        client.setDomain(domain);
                                        client.setEmail(email);
                                        result += "UPDATED " + client + "\n";
                                    }
                                    Client.store();
                                }
                            } else {
                                result = "ERROR: COMMAND\n";
                            }
                        } else {
                            result = "ERROR: COMMAND\n";
                        }
                    } else {
                        result = "ERROR: COMMAND\n";
                    }
                } else if (token.equals("USER") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.hasMoreTokens()) {
                        String email = tokenizer.nextToken();
                        if (tokenizer.hasMoreTokens()) {
                            String name = tokenizer.nextToken();
                            while (tokenizer.hasMoreElements()) {
                                name += ' ' + tokenizer.nextToken();
                            }
                            try {
                                User user = User.create(email, name);
                                if (user == null) {
                                    result = "ALREADY EXISTS\n";
                                } else {
                                    result = "ADDED " + user + "\n";
                                }
                            } catch (ProcessException ex) {
                                result = ex.getMessage() + "\n";
                            }
                            User.store();
                        } else {
                            result = "ERROR: COMMAND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            TreeSet<User> userSet = User.dropAll();
                            if (userSet.isEmpty()) {
                                result = "EMPTY\n";
                            } else {
                                for (User user : userSet) {
                                    result += "DROPED " + user + "\n";
                                }
                            }
                        } else {
                            User user = User.drop(token);
                            if (user == null) {
                                result = "NOT FOUND\n";
                            } else {
                                result = "DROPED " + user + "\n";
                            }
                        }
                        User.store();
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        for (User user : User.getSet()) {
                            result += user + "\n";
                        }
                        if (result.length() == 0) {
                            result = "EMPTY\n";
                        }
                    } else {
                        result = "ERROR: COMMAND\n";
                    }
                } else if (token.equals("PEER") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") &&  tokenizer.hasMoreTokens()) {
                        String service = tokenizer.nextToken();
                        String email = null;
                        if (tokenizer.hasMoreElements()) {
                            email = tokenizer.nextToken();
                        }
                        int index = service.indexOf(':');
                        if (index == -1) {
                            result = "ERROR: COMMAND\n";
                        } else if (email != null && !Domain.isEmail(email)) {
                            result = "ERROR: INVALID EMAIL\n";
                        } else {
                            String address = service.substring(0, index);
                            String port = service.substring(index + 1);
                            Peer peer = Peer.create(address, port);
                            if (peer == null) {
                                result = "ALREADY EXISTS\n";
                            } else {
                                peer.setEmail(email);
                                peer.sendHELO();
                                result = "ADDED " + peer + "\n";
                            }
                            Peer.store();
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            TreeSet<Peer> peerSet = Peer.dropAll();
                            if (peerSet.isEmpty()) {
                                result = "EMPTY\n";
                            } else {
                                for (Peer peer : peerSet) {
                                    result += "DROPED " + peer + "\n";
                                }
                            }
                        } else {
                            Peer peer = Peer.drop(token);
                            result = (peer == null ? "NOT FOUND" : "DROPED " + peer) + "\n";
                        }
                        Peer.store();
                    } else if (token.equals("SHOW")) {
                        if (!tokenizer.hasMoreTokens()) {
                            for (Peer peer : Peer.getSet()) {
                                result += peer + "\n";
                            }
                            if (result.length() == 0) {
                                result = "EMPTY\n";
                            }
                        } else if (tokenizer.countTokens() == 1) {
                            String address = tokenizer.nextToken();
                            Peer peer = Peer.get(address);
                            if (peer == null) {
                                result = "NOT FOUND " + address + "\n";
                            } else {
                                result = peer + "\n";
                                for (String confirm : peer.getRetationSet()) {
                                    result += confirm + "\n";
                                }
                            }
                        } else {
                            result = "ERROR: COMMAND\n";
                        }
                    } else if (token.equals("SET") && tokenizer.countTokens() == 3) {
                        String address = tokenizer.nextToken();
                        String send = tokenizer.nextToken();
                        String receive = tokenizer.nextToken();
                        Peer peer = Peer.get(address);
                        if (peer == null) {
                            result = "NOT FOUND " + address + "\n";
                        } else {
                            result = peer + "\n";
                            try {
                                result += (peer.setSendStatus(send) ? "UPDATED" : "ALREADY") + " SEND=" + send + "\n";
                            } catch (ProcessException ex) {
                                result += "NOT RECOGNIZED '" + send + "'\n";
                            }
                            try {
                                result += (peer.setReceiveStatus(receive) ? "UPDATED" : "ALREADY") + " RECEIVE=" + receive + "\n";
                            } catch (ProcessException ex) {
                                result += "NOT RECOGNIZED '" + receive + "'\n";
                            }
                            Peer.store();
                        }
                    } else if (token.equals("PING") && tokenizer.countTokens() == 1) {
                        String address = tokenizer.nextToken();
                        Peer peer = Peer.get(address);
                        if (peer == null) {
                            result = "NOT FOUND " + address + "\n";
                        } else if (peer.sendHELO()) {
                            result = "HELO SENT TO " + address + "\n";
                        } else {
                            result = "HELO NOT SENT local hostname is invalid\n";
                        }
                    } else if (token.equals("SEND") && tokenizer.countTokens() == 1) {
                        String address = tokenizer.nextToken();
                        Peer peer = Peer.get(address);
                        if (peer == null) {
                            result = "NOT FOUND " + address + "\n";
                        } else {
                            peer.sendAll();
                            result = "SENT TO " + address + "\n";
                        }
                    } else if (token.equals("RETENTION") && tokenizer.hasMoreElements()) {
                        token = tokenizer.nextToken();
                        if (token.equals("SHOW") && tokenizer.countTokens() == 1) {
                            token = tokenizer.nextToken();
                            if (token.equals("ALL")) {
                                TreeSet<String> retationSet = Peer.getAllRetationSet();
                                if (retationSet.isEmpty()) {
                                    result = "EMPTY\n";
                                } else {
                                    for (String tokenRetained : retationSet) {
                                        result += tokenRetained + '\n';
                                    }
                                }
                            } else if (Domain.isHostname(token)) {
                                Peer peer = Peer.get(token);
                                if (peer == null) {
                                    result = "PEER '" + token + "' NOT FOUND\n";
                                } else {
                                    TreeSet<String> retationSet = peer.getRetationSet();
                                    if (retationSet.isEmpty()) {
                                        result = "EMPTY\n";
                                    } else {
                                        for (String tokenRetained : retationSet) {
                                            result += tokenRetained + '\n';
                                        }
                                    }
                                }
                            } else {
                                result = "ERROR: COMMAND\n";
                            }
                        } else if (token.equals("RELEASE")) {
                            token = tokenizer.nextToken();
                            if (token.equals("ALL")) {
                                TreeSet<String> returnSet = Peer.releaseAll();
                                if (returnSet.isEmpty()) {
                                    result = "EMPTY\n";
                                } else {
                                    for (String response : returnSet) {
                                        result += response + '\n';
                                    }
                                }
                            } else {
                                TreeSet<String> returnSet = Peer.releaseAll(token);
                                if (returnSet.isEmpty()) {
                                    result = "EMPTY\n";
                                } else {
                                    for (String response : returnSet) {
                                        result += response + '\n';
                                    }
                                }
                            }
                        } else if (token.equals("REJECT")) {
                            token = tokenizer.nextToken();
                            if (token.equals("ALL")) {
                                TreeSet<String> returnSet = Peer.rejectAll();
                                if (returnSet.isEmpty()) {
                                    result = "EMPTY\n";
                                } else {
                                    for (String response : returnSet) {
                                        result += response + '\n';
                                    }
                                }
                            } else {
                                TreeSet<String> returnSet = Peer.rejectAll(token);
                                if (returnSet.isEmpty()) {
                                    result = "EMPTY\n";
                                } else {
                                    for (String response : returnSet) {
                                        result += response + '\n';
                                    }
                                }
                            }
                        } else {
                            result = "ERROR: COMMAND\n";
                        }
                    } else {
                        result = "ERROR: COMMAND\n";
                    }
                } else if (token.equals("GUESS") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") &&  tokenizer.hasMoreTokens()) {
                        // Comando para adicionar um palpite SPF.
                        String domain = tokenizer.nextToken();
                        int beginIndex = command.indexOf('"') + 1;
                        int endIndex = command.lastIndexOf('"');
                        if (beginIndex > 0 && endIndex > beginIndex) {
                            String spf = command.substring(beginIndex, endIndex);
                            boolean added = SPF.addGuess(domain, spf);
                            result = (added ? "ADDED" : "REPLACED") + "\n";
                            SPF.storeGuess();
                            SPF.storeSPF();
                        } else {
                            result = "ERROR: COMMAND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            TreeSet<String> guessSet = SPF.dropAllGuess();
                            if (guessSet.isEmpty()) {
                                result = "EMPTY\n";
                            } else {
                                for (String guess : guessSet) {
                                    result += "DROPED " + guess + "\n";
                                }
                            }
                        } else {
                            boolean droped = SPF.dropGuess(token);
                            result = (droped ? "DROPED" : "NOT FOUND") + "\n";
                        }
                        SPF.storeGuess();
                        SPF.storeSPF();
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        for (String guess : SPF.getGuessSet()) {
                            result += guess + "\n";
                        }
                        if (result.length() == 0) {
                            result = "EMPTY\n";
                        }
                    } else {
                        result = "ERROR: COMMAND\n";
                    }
                } else if (token.equals("REPUTATION")) {
                    // Comando para verificar a reputação dos tokens.
                    StringBuilder stringBuilder = new StringBuilder();
                    TreeMap<String,Distribution> distributionMap;
                    if (tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (token.equals("ALL")) {
                            distributionMap = SPF.getDistributionMap();
                        } else if (token.equals("IPV4")) {
                            distributionMap = SPF.getDistributionMapIPv4();
                        } else if (token.equals("IPV6")) {
                            distributionMap = SPF.getDistributionMapIPv6();
                        } else {
                            distributionMap = null;
                        }
                    } else {
                        distributionMap = SPF.getDistributionMap();
                    }
                    if (distributionMap == null) {
                        result = "ERROR: COMMAND\n";
                    } else if (distributionMap.isEmpty()) {
                        result = "EMPTY\n";
                    } else {
                        for (String tokenReputation : distributionMap.keySet()) {
                            Distribution distribution = distributionMap.get(tokenReputation);
                            float probability = distribution.getSpamProbability(tokenReputation);
                            if (probability >= 0.01f) {
                                Status status = distribution.getStatus(tokenReputation);
                                stringBuilder.append(tokenReputation);
                                stringBuilder.append(' ');
                                stringBuilder.append(status);
                                stringBuilder.append(' ');
                                stringBuilder.append(DECIMAL_FORMAT.format(probability));
                                stringBuilder.append('\n');
                            }
                        }
                        result = stringBuilder.toString();
                    }
                } else if (token.equals("CLEAR") && tokenizer.countTokens() == 1) {
                    try {
                        token = tokenizer.nextToken();
                        TreeSet<String> clearSet = SPF.clear(token);
                        if (clearSet.isEmpty()) {
                            result += "NOT FOUND\n";
                        } else {
                            for (String value : clearSet) {
                                result += value + '\n';
                            }
                        }
                    } catch (Exception ex) {
                        result += ex.getMessage() + "\n";
                    }
                    SPF.storeDistribution();
                    SPF.storeBlock();
                } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                    // Comando para apagar registro em cache.
                    while (tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (Owner.isOwnerID(token)) {
                            Owner.removeOwner(token);
                            result += "OK\n";
                        } else if (SubnetIPv4.isValidIPv4(token)) {
                            SubnetIPv4.removeSubnet(token);
                            result += "OK\n";
                        } else if (SubnetIPv6.isValidIPv6(token)) {
                            SubnetIPv6.removeSubnet(token);
                            result += "OK\n";
                        } else if (Domain.containsDomain(token)) {
                            Domain.removeDomain(token);
                            result += "OK\n";
                        } else {
                            result += "UNDEFINED\n";
                        }
                    }
                } else if (token.equals("REFRESH") && tokenizer.hasMoreTokens()) {
                    // Comando para atualizar registro em cache.
                    while (tokenizer.hasMoreTokens()) {
                        token = tokenizer.nextToken();
                        if (Owner.isOwnerID(token)) {
                            Owner.refreshOwner(token);
                            result += "OK\n";
                        } else if (SubnetIPv4.isValidIPv4(token)) {
                            SubnetIPv4.refreshSubnet(token);
                            result += "OK\n";
                        } else if (SubnetIPv6.isValidIPv6(token)) {
                            SubnetIPv6.refreshSubnet(token);
                        } else if (Domain.containsDomain(token)) {
                            Domain.refreshDomain(token);
                            result += "OK\n";
                        } else {
                            result += "UNDEFINED\n";
                        }
                    }
                } else {
                    result = "ERROR: COMMAND\n";
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
    
    private static String splitCIDR(String cidr) {
        String result = "";
        String first = Subnet.getFirstIP(cidr);
        String last = Subnet.getLastIP(cidr);
        byte mask = Subnet.getMask(cidr);
        byte max;
        if (SubnetIPv4.isValidIPv4(first)) {
            max = 32;
        } else {
            max = 64;
        }
        if (mask < max) {
            mask++;
            String cidr1 = first + "/" + mask;
            String cidr2 = last + "/" + mask;
            cidr1 = Subnet.normalizeCIDR(cidr1);
            cidr2 = Subnet.normalizeCIDR(cidr2);
            try {
                if (SPF.addBlock(cidr1) == null) {
                    result += "EXISTS " + cidr1 + "\n";
                } else {
                    result += "ADDED " + cidr1 + "\n";
                }
            } catch (ProcessException ex) {
                result += splitCIDR(cidr1);
            }
            try {
                if (SPF.addBlock(cidr2) == null) {
                    result += "EXISTS " + cidr2 + "\n";
                } else {
                    result += "ADDED " + cidr2 + "\n";
                }
            } catch (ProcessException ex) {
                result += splitCIDR(cidr2);
            }
        } else {
            result += "UNSPLITTABLE " + cidr + "\n";
        }
        return result;
    }
}
