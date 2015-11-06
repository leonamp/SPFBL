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
import java.util.StringTokenizer;
import java.util.Timer;
import java.util.TimerTask;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
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
        SPF.load();
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
        SPF.store();
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
    private static final SimpleDateFormat FORMAT_DATE_LOG = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
    
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
    public static final int DAY_TIME = 1000 * 60 * 60 * 24;
    
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
    private static void log(long time, String type, String message, String result) {
        int latencia = (int) (System.currentTimeMillis() - time);
        if (latencia > 9999) {
            // Para manter a formatação correta no LOG,
            // Registrar apenas latências até 9999, que tem 4 digitos.
            latencia = 9999;
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
                + " " + type + " " + message
                + (result == null ? "" : " => " + result);
        PrintWriter writer = getLogWriter(date);
        if (writer == null) {
            System.out.println(text);
        } else {
            writer.println(text);
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
    private static final DecimalFormat LATENCIA_FORMAT = new DecimalFormat("0000");
    
    private static void log(long time,
            String type,
//            String message,
            Throwable ex) {
        if (ex != null) {
//            log(time, type, message, (String) null);
//        } else {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PrintStream printStream = new PrintStream(baos);
            ex.printStackTrace(printStream);
            printStream.close();
            log(time, type, baos.toString(), (String) null);
        }
    }
    
    /**
     * Registra as mensagens para depuração.
     * @param message a mensagem a ser registrada.
     */
    public static void logDebug(String message) {
        log(System.currentTimeMillis(), "DEBUG", message, (String) null);
    }
    
    /**
     * Registra as gravações de cache em disco.
     * @param file o arquivo armazenado.
     */
    public static void logStore(long time, File file) {
        log(time, "STORE", file.getName(), (String) null);
    }
    
    /**
     * Registra os carregamentos de cache no disco.
     * @param file o arquivo carregado.
     */
    public static void logLoad(long time, File file) {
        log(time, "LOADC", file.getName(), (String) null);
    }
    
    /**
     * Registra as mensagens de checagem DNS.
     * @param host o host que foi consultado.
     */
    public static void logCheckDNS(
            long time, String host, String result) {
        log(time, "DNSCK", host, result);
    }
    
    /**
     * Registra os tiquetes processados.
     * @param tokenSet o conjunto de tokens.
     */
    public static void logTicket(long time, 
            String ip, String sender, String helo,
            TreeSet<String> tokenSet, String ticket) {
        if (sender == null) {
            log(time, "TIKET", ip + " " + helo + " " + tokenSet, ticket);
        } else {
            log(time, "TIKET", ip + " " + sender + " " + helo + " " + tokenSet, ticket);
        }
    }
    
    public static void logPeerSend(long time,
            String address, String token, String result) {
        logQuery(time, "PEERS", address, token, result);
    }
    
    /**
     * Registra as consultas DNS.
     */
    public static void logLookupDNS(long time, 
            String type, String host, String result) {
        log(time, "DNSLK", type + " " + host, result);
    }
    
    /**
     * Registra as consultas DNS para HELO.
     */
    public static void logLookupHELO(long time, 
            String host, String result) {
        log(time, "HELOL", host, result);
    }
    
    /**
     * Registra as consultas de mecanismo A de SPF.
     */
    public static void logMecanismA(long time, 
            String host, String result) {
        log(time, "SPFMA", host, result);
    }
    
    /**
     * Registra as consultas de mecanismo exists de SPF.
     */
    public static void logMecanismExists(long time, 
            String host, String result) {
        log(time, "SPFEX", host, result);
    }
    
    /**
     * Registra as consultas de mecanismo MX de SPF.
     */
    public static void logMecanismMX(long time, 
            String host, String result) {
        log(time, "SPFMX", host, result);
    }
    
    /**
     * Registra verificações de macth de HELO.
     */
    public static void logMatchHELO(long time, 
            String query, String result) {
        log(time, "HELOM", query, result);
    }
    
    /**
     * Registra interações de atrazo programado.
     */
    public static void logDefer(long time, 
            String id, String result) {
        log(time, "DEFER", id, result);
    }
    
    /**
     * Registra verificações de DNS reverso.
     */
    public static void logReverseDNS(long time, 
            String ip, String result) {
        log(time, "DNSRV", ip, result);
    }
    
    /**
     * Registra as mensagens de erro.
     * @param message a mensagem a ser registrada.
     */
    public static void logError(String message) {
        log(System.currentTimeMillis(), "ERROR", message, (String) null);
    }
    
    /**
     * Registra as mensagens de erro.
     * Uma iniciativa para formalização das mensagens de log.
     * @param ex a exceção a ser registrada.
     */
    public static void logError(Throwable ex) {
        if (ex instanceof ProcessException) {
            ProcessException pex = (ProcessException) ex;
            log(System.currentTimeMillis(), "ERROR", pex.getErrorMessage(), (String) null);
        } else if (ex instanceof Exception) {
            log(System.currentTimeMillis(), "ERROR", ex);
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
        log(time, "SPFLK", hostname, result);
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
        log(time, "WHOIS", server + " " + query, result);
    }
    
    private static long lastClientsFileModified = 0;
    private static final TreeMap<String,String> subnetClientsMap = new TreeMap<String,String>();
    
    @Deprecated
    public static synchronized String getLogClientOld(InetAddress address) {
        if (address == null) {
            return "UNKNOWN";
        } else {
            File clientsFile = new File("./data/clients.txt");
            if (!clientsFile.exists()) {
                subnetClientsMap.clear();
            } else if (clientsFile.lastModified() > lastClientsFileModified) {
                try {
                    subnetClientsMap.clear();
                    BufferedReader reader = new BufferedReader(new FileReader(clientsFile));
                    try {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            StringTokenizer tokenizer = new StringTokenizer(line, "\t");
                            if (tokenizer.countTokens() == 3) {
                                String cidr = tokenizer.nextToken();
                                String email = tokenizer.nextToken();
                                subnetClientsMap.put(cidr, email);
                            }
                        }
                        lastClientsFileModified = clientsFile.lastModified();
                    } finally {
                        reader.close();
                    }
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
            String ip = address.getHostAddress();
            try {
                for (String cidr : subnetClientsMap.keySet()) {
                    if (SubnetIPv4.isValidCIDRv4(cidr)) {
                        int mask = SubnetIPv4.getMaskNet(cidr);
                        int address1 = SubnetIPv4.getAddressNet(cidr) & mask;
                        int address2 = SubnetIPv4.getAddressIP(ip) & mask;
                        if (address1 == address2) {
                            return subnetClientsMap.get(cidr);
                        }
                    } else if (SubnetIPv6.isValidIPv6(cidr)) {
                        int index = cidr.indexOf('/');
                        short[] mask = SubnetIPv6.getMaskIPv6(cidr.substring(index));
                        short[] address1 = SubnetIPv6.split(cidr.substring(0, index), mask);
                        short[] address2 = SubnetIPv6.split(ip, mask);
                        if (Arrays.equals(address1, address2)) {
                            return subnetClientsMap.get(cidr);
                        }
                    }
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
            return ip;
        }
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
            log(time, type, origin + ":", result);
        } else {
            log(time, type, origin + ": " + query, result);
        }
    }
    
    public static void logQuery(
            long time,
            String type,
            String client,
            String query, String result) {
        log(time, type, (client == null ? "" : client + ": ") + query, result);
    }
    
    /**
     * Registra as mensagens de comando.
     * Uma iniciativa para formalização das mensagens de log.
     * @param ipAddress o IP da conexão.
     * @param command a expressão do comando.
     * @param result a expressão do resultado.
     */
    public static void logCommand(long time,
            InetAddress ipAddress, String command, String result) {
        String origin = Client.getOrigin(ipAddress);
        log(time, "CMMND", origin + ": " + command, result);
    }
    
    /**
     * Desliga todos os servidores instanciados.
     * @throws Exception se houver falha no fechamento de algum servidor.
     */
    public static boolean shutdown() {
        // Inicia finalização dos servidores.
        Server.logDebug("shutting down server...");
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
        SPF.cancel();
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
    private static final Timer WHOIS_SEMAPHORE_TIMER = new Timer("TimerWHOIS");
    
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
    public static void removeWhoisQuery() throws ProcessException {
        WhoisSemaphore whoisSemaphore = new WhoisSemaphore();
        WHOIS_SEMAPHORE_TIMER.schedule(whoisSemaphore, DAY_TIME);
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
            WHOIS_CONNECTION_SEMAPHORE.acquire();
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
            Hashtable env = new Hashtable();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            env.put("com.sun.jndi.dns.timeout.initial", "3000");
            env.put("com.sun.jndi.dns.timeout.retries", "1");
            INITIAL_DIR_CONTEXT = new InitialDirContext(env);
        } catch (Exception ex) {
            Server.logError(ex);
            System.exit(1);
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
        long time = System.currentTimeMillis();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            WHOIS_CONNECTION_SEMAPHORE.acquire();
            try {
                acquireWhoisQuery();
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
    
    public static synchronized void tryBackugroundRefresh() {
        // Evita que muitos processos fiquem 
        // presos aguardando a liberação do método.
        if (WHOIS_QUERY_SEMAPHORE.availablePermits() == WHOIS_QUERY_LIMIT) {
            backgroundRefresh();
        }
    }
    
    /**
     * Atualiza os registros quase expirando.
     */
    public static synchronized boolean backgroundRefresh() {
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
                if (token.equals("SHUTDOWN") && !tokenizer.hasMoreTokens()) {
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
                        while (tokenizer.hasMoreTokens()) {
                            try {
                                token = tokenizer.nextToken();
                                if (Domain.removeTLD(token)) {
                                    result += "DROPED\n";
                                } else {
                                    result += "NOT FOUND\n";
                                }
                            } catch (ProcessException ex) {
                                result += ex.getMessage() + "\n";
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
                    if (token.equals("ADD") && tokenizer.countTokens() >= 3) {
                        try {
                            String hostname = tokenizer.nextToken();
                            String address = tokenizer.nextToken();
                            InetAddress inetAddress = InetAddress.getByName(address);
                            String message = tokenizer.nextToken();
                            while (tokenizer.hasMoreTokens()) {
                                message += ' ' + tokenizer.nextToken();
                            }
                            if (QueryDNSBL.add(hostname, inetAddress, message)) {
                                result = "ADDED\n";
                            } else {
                                result = "ALREADY EXISTS\n";
                            }
                            QueryDNSBL.store();
                        } catch (UnknownHostException ex) {
                            result = "INVALID ADDRESS\n";
                        }
                    } else if (token.equals("SET") && tokenizer.countTokens() >= 3) {
                        try {
                            String hostname = tokenizer.nextToken();
                            String address = tokenizer.nextToken();
                            InetAddress inetAddress = InetAddress.getByName(address);
                            String message = tokenizer.nextToken();
                            while (tokenizer.hasMoreTokens()) {
                                message += ' ' + tokenizer.nextToken();
                            }
                            if (QueryDNSBL.set(hostname, inetAddress, message)) {
                                result = "UPDATED\n";
                            } else {
                                result = "NOT FOUND\n";
                            }
                            QueryDNSBL.store();
                        } catch (UnknownHostException ex) {
                            result = "INVALID ADDRESS\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        while (tokenizer.hasMoreTokens()) {
                            token = tokenizer.nextToken();
                            if (QueryDNSBL.drop(token)) {
                                result += "DROPED\n";
                            } else {
                                result += "NOT FOUND\n";
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
                                result += server + " " + server.getHostAddress() + " " + server.getMessage() + "\n";
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
                        // Comando para adicionar provedor de e-mail.
                        while (tokenizer.hasMoreTokens()) {
                            try {
                                String provider = tokenizer.nextToken();
                                if (SPF.dropProvider(provider)) {
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
                        // Comando para adicionar provedor de e-mail.
                        while (tokenizer.hasMoreTokens()) {
                            try {
                                String ignore = tokenizer.nextToken();
                                if (SPF.dropIgnore(ignore)) {
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
                                if (SPF.addBlock(blockedToken)) {
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
                        while (tokenizer.hasMoreElements()) {
                            try {
                                String blockedToken = tokenizer.nextToken();
                                if (SPF.dropBlock(blockedToken)) {
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
                                if (SPF.addWhite(whiteToken)) {
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
                        while (tokenizer.hasMoreElements()) {
                            try {
                                String whiteedToken = tokenizer.nextToken();
                                if (SPF.dropWhite(whiteedToken)) {
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
                } else if (token.equals("CLIENT") && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                    if (token.equals("ADD") && tokenizer.hasMoreTokens()) {
                        String cidr = tokenizer.nextToken();
                        if (tokenizer.hasMoreTokens()) {
                            String domain = tokenizer.nextToken();
                            String email;
                            if (tokenizer.hasMoreTokens()) {
                                if (tokenizer.countTokens() == 1) {
                                    email = tokenizer.nextToken();
                                } else {
                                    email = null;
                                }
                            } else {
                                email = "";
                            }
                            if (email == null) {
                                result = "ERROR: COMMAND\n";
                            } else {
                                try {
                                    Client client = Client.create(cidr, domain, email);
                                    if (client == null) {
                                        result = "ALREADY EXISTS\n";
                                    } else {
                                        result = "ADDED " + client + "\n";
                                    }
                                } catch (ProcessException ex) {
                                    result = ex.getMessage() + "\n";
                                }
                                Client.store();
                            }
                        } else {
                            result = "ERROR: COMMAND\n";
                        }
                    } else if (token.equals("DROP") && tokenizer.hasMoreTokens()) {
                        String cidr = tokenizer.nextToken();
                        Client client = Client.drop(cidr);
                        if (client == null) {
                            result += "NOT FOUND\n";
                        } else {
                            result += "DROPED " + client + "\n";
                        }
                        Client.store();
                    } else if (token.equals("SHOW") && !tokenizer.hasMoreTokens()) {
                        for (Client client : Client.getSet()) {
                            result += client + "\n";
                        }
                        if (result.length() == 0) {
                            result = "EMPTY\n";
                        }
                    } else if (token.equals("SET") && tokenizer.hasMoreTokens()) {
                        String cidr = tokenizer.nextToken();
                        String domain = tokenizer.nextToken();
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
                                client.setDomain(domain);
                                client.setEmail(email);
                                result += "UPDATED " + client + "\n";
                            }
                            Client.store();
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
                        String email = tokenizer.nextToken();
                        User user = User.drop(email);
                        if (user == null) {
                            result += "NOT FOUND\n";
                        } else {
                            result += "DROPED " + user + "\n";
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
                        String address = tokenizer.nextToken();
                        Peer peer = Peer.drop(address);
                        result = (peer == null ? "NOT FOUND" : "DROPED " + peer) + "\n";
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
                                for (String confirm : peer.getConfirmSet()) {
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
                        String domain = tokenizer.nextToken();
                        boolean droped = SPF.dropGuess(domain);
                        result = (droped ? "DROPED" : "NOT FOUND") + "\n";
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
                            float probability = distribution.getMinSpamProbability();
                            Status status = distribution.getStatus(tokenReputation);
                            String frequency = distribution.getFrequencyLiteral();
                            stringBuilder.append(tokenReputation);
                            stringBuilder.append(' ');
                            stringBuilder.append(frequency);
                            stringBuilder.append(' ');
                            stringBuilder.append(status);
                            stringBuilder.append(' ');
                            stringBuilder.append(DECIMAL_FORMAT.format(probability));
                            stringBuilder.append('\n');
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
}
