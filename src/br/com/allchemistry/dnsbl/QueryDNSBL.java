/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.com.allchemistry.dnsbl;

import br.com.allchemistry.core.Server;
import br.com.allchemistry.spf.SPF;
import br.com.allchemistry.whois.Domain;
import br.com.allchemistry.whois.Subnet;
import br.com.allchemistry.whois.SubnetIPv4;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.LinkedList;
import java.util.concurrent.Semaphore;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Opcode;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.TXTRecord;

/**
 * Servidor de consulta DNSBL.
 * 
 * @author Leandro Carlos Rodrigues <leandro@allchemistry.com.br>
 */
public final class QueryDNSBL extends Server {

    private final int PORT = 53;
    private final DatagramSocket SERVER_SOCKET;
    
    /**
     * Configuração e intanciamento do servidor.
     * @throws java.net.SocketException se houver falha durante o bind.
     */
    public QueryDNSBL() throws SocketException {
        super("ServerDNSBL");
        // Criando conexões.
        Server.logDebug("Binding DNSBL socket on port " + PORT + "...");
        SERVER_SOCKET = new DatagramSocket(PORT);
    }
    
    /**
     * Representa uma conexão ativa.
     * Serve para processar todas as requisições.
     */
    private class Connection extends Thread {
        
        /**
         * O poll de pacotes de consulta a serem processados.
         */
        private final LinkedList<DatagramPacket> PACKET_LIST = new LinkedList<DatagramPacket>();
        
        /**
         * Semáforo que controla o pool de pacotes.
         */
        private final Semaphore PACKET_SEMAPHORE = new Semaphore(0);
        
        public Connection() {
            super("DNSBL" + (CONNECTION_COUNT+1));
            // Toda connexão recebe prioridade mínima.
            setPriority(Thread.MIN_PRIORITY);
        }
        
        /**
         * Processa um pacote de consulta.
         * @param packet o pacote de consulta a ser processado.
         */
        private synchronized void process(DatagramPacket packet) {
            PACKET_LIST.offer(packet);
            if (isAlive()) {
                // Libera o próximo processamento.
                PACKET_SEMAPHORE.release();
            } else {
                // Inicia a thread pela primmeira vez.
                start();
            }
        }
        
        /**
         * Fecha esta conexão liberando a thread.
         */
        private void close() {
            Server.logDebug("Closing " + getName() + "...");
            PACKET_SEMAPHORE.release();
        }
        
        /**
         * Aguarda nova chamada.
         */
        private void waitCall() {
            try {
                PACKET_SEMAPHORE.acquire();
            } catch (InterruptedException ex) {
                Server.logError(ex);
            }
        }
        
        /**
         * Processamento da consulta e envio do resultado.
         * Aproveita a thead para realizar procedimentos em background.
         */
        @Override
        public void run() {
            while (!PACKET_LIST.isEmpty()) {
                try {
                    DatagramPacket packet = PACKET_LIST.poll();
                    byte[] data = packet.getData();
                    String result;
                    // Processando consulta DNS.
                    Message message = new Message(data);
                    Header header = message.getHeader();
                    Record question = message.getQuestion();
                    Name name = question.getName();
                    String query = name.toString();
//                    String txtMessage = "You are listed in this server.";
                    int index = query.indexOf(".dnsbl.allchemistry.com.br.");
                    boolean listed = false;
                    String token = null;
                    long ttl = 0; // Tempo de cache.
                    if (index > 0) {
                        token = query.substring(0, index);
                        String ownerid;
                        if (SubnetIPv4.isValidIPv4(token)) {
                            // A consulta é um IPv4.
                            // Reverter ordem dos octetos.
                            byte[] address = SubnetIPv4.split(token);
                            byte octeto = address[0];
                            String ip = Integer.toString((int) octeto & 0xFF);
                            for (int i = 1; i < address.length; i++) {
                                octeto = address[i];
                                ip = ((int) octeto & 0xFF) + "." + ip;
                            }
                            ip = SubnetIPv4.correctIP(ip);
                            if (SPF.isBlacklisted(ip)) {
                                listed = true;
                                ttl = SPF.getComplainTTL(ip);
                                token = "IP " + ip;
                            } else if ((ownerid = Subnet.getOwnerID(ip)) != null) {
                                listed = SPF.isBlacklisted(ownerid);
                                ttl = SPF.getComplainTTL(ownerid);
                                token = "Ownerid " + ownerid;
                            }
                        } else if (Domain.containsDomain(token)) {
                            String host = Domain.extractHost(token, true);
                            String domain = Domain.extractDomain(token, true);
                            if (SPF.isBlacklisted(host)) {
                                listed = true;
                                ttl = SPF.getComplainTTL(host);
                                token = "Host " + host;
                            } else if (SPF.isBlacklisted(domain)) {
                                listed = true;
                                ttl = SPF.getComplainTTL(domain);
                                token = "Domain " + domain;
                            } else if ((ownerid = Domain.getOwnerID(domain)) != null) {
                                listed = SPF.isBlacklisted(ownerid);
                                ttl = SPF.getComplainTTL(ownerid);
                                token = "Ownerid " + ownerid;
                            }
                        } else {
                            listed = SPF.isBlacklisted(token);
                            ttl = SPF.getComplainTTL(token);
                        }
                    }
                    // Alterando mensagem DNS para resposta.
                    header.setFlag(Flags.QR);
                    header.setFlag(Flags.AA);
                    if (listed) {
                        // Está listado.
                        result = "127.0.0.2";
                        String txtMessage = token + " is listed in this server.";
                        InetAddress resultAddress = InetAddress.getByName(result);
                        ARecord anwser = new ARecord(name, DClass.IN, ttl, resultAddress);
                        TXTRecord txt = new TXTRecord(name, DClass.IN, ttl, txtMessage);
                        message.addRecord(anwser, Section.ANSWER);
                        message.addRecord(txt, Section.ANSWER);
                        result += " " + txtMessage;
                    } else {
                        // Não está listado.
                        result = "NXDOMAIN";
                        header.setRcode(Rcode.NXDOMAIN);
                    }
                    // Enviando resposta.
                    InetAddress ipAddress = packet.getAddress();
                    int portDestiny = packet.getPort();
                    byte[] sendData = message.toWire();
                    DatagramPacket sendPacket = new DatagramPacket(
                            sendData, sendData.length,
                            ipAddress, portDestiny
                            );
                    SERVER_SOCKET.send(sendPacket);
                    // Log da consulta com o respectivo resultado.
                    Server.logQueryDNSBL(ipAddress, query, result);
                } catch (Exception ex) {
                    Server.logError(ex);
                } finally {
                    // Atualiza registros quase expirando durante a consulta.
                    Server.tryBackugroundRefresh();
                    // Armazena todos os registros atualizados durante a consulta.
                    Server.storeCache();
                    // Oferece a conexão ociosa na última posição da lista.
                    CONNECTION_POLL.offer(this);
                    CONNECION_SEMAPHORE.release();
                    // Aguarda nova chamada.
                    waitCall();
                }
            }
        }
    }
    
    /**
     * Pool de conexões ativas.
     */
    private final LinkedList<Connection> CONNECTION_POLL = new LinkedList<Connection>();
    
    /**
     * Semáforo que controla o pool de conexões.
     */
    private final Semaphore CONNECION_SEMAPHORE = new Semaphore(0);
    
    /**
     * Quantidade total de conexões intanciadas.
     */
    private int CONNECTION_COUNT = 0;
    
    /**
     * Coleta uma conexão ociosa ou inicia uma nova.
     * @return uma conexão ociosa ou nova se não houver ociosa.
     */
    private Connection pollConnection() {
        if (CONNECION_SEMAPHORE.tryAcquire()) {
            return CONNECTION_POLL.poll();
        } else {
            // Cria uma nova conexão se não houver conecxões ociosas.
            // O servidor aumenta a capacidade conforme a demanda.
            Server.logDebug("Creating DNSBL" + (CONNECTION_COUNT+1) + "...");
            Connection connection = new Connection();
            CONNECTION_COUNT++;
            return connection;
        }
    }
    
    /**
     * Inicialização do serviço.
     */
    @Override
    public synchronized void run() {
        try {
            Server.logDebug("Listening DNSBL on UDP port " + PORT + "...");
            while (continueListenning()) {
                try {
                    byte[] receiveData = new byte[1024];
                    DatagramPacket packet = new DatagramPacket(
                            receiveData, receiveData.length);
                    SERVER_SOCKET.receive(packet);
                    Connection connection = pollConnection();
                    if (connection == null) {
                        InetAddress ipAddress = packet.getAddress();
                        int portDestiny = packet.getPort();
                        String result = "ERROR: TOO MANY CONNECTIONS\n";
                        byte[] sendData = result.getBytes("ISO-8859-1");
                        DatagramPacket sendPacket = new DatagramPacket(
                                sendData, sendData.length,
                                ipAddress, portDestiny
                                );
                        SERVER_SOCKET.send(sendPacket);
                        System.out.print(result);
                    } else {
                        connection.process(packet);
                    }
                } catch (SocketException ex) {
                    // Conexão fechada externamente pelo método close().
                }
            }
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
            Server.logDebug("Querie DNSBL server closed.");
        }
    }
    
    /**
     * Fecha todas as conexões e finaliza o servidor UDP.
     * @throws Exception se houver falha em algum fechamento.
     */
    @Override
    protected void close() throws Exception {
        while (CONNECTION_COUNT > 0) {
            CONNECION_SEMAPHORE.acquire();
            Connection connection = CONNECTION_POLL.poll();
            connection.close();
            CONNECTION_COUNT--;
        }
        Server.logDebug("Unbinding DSNBL socket on port " + PORT + "...");
        SERVER_SOCKET.close();
    }
}
