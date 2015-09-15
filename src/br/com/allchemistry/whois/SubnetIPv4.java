/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.com.allchemistry.whois;

import br.com.allchemistry.core.Server;
import br.com.allchemistry.core.ProcessException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Pattern;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Representa uma Subnet de IPv4.
 * 
 * <h2>Mecanismo de busca</h2>
 * A busca de um bloco AS é realizada através de um mapa ordenado em árvore,
 * onde a chave é o primeiro endereço IP do bloco, 
 * convetido em inteiro de 32 bits, e o valor é o bloco propriamente dito.
 * O endereço IP da consulta é convertido em inteiro de 32 bits e localiza-se 
 * o endereço no mapa imediatamente inferior ou igual ao endereço do IP. 
 * Por conta do Java não trabalhar com unsigned int, 
 * a busca é feita de forma circular, ou seja, 
 * se não retornar na primeira busca, o último registro do mapa é retornado.
 * Se algum bloco for encontrado, 
 * é feito um teste se o endereço do IP está contido no bloco encontrado.
 * Se entiver dentro, o bloco encontrado é considerado.
 * A busca consome o tempo de O(log2(n)).
 * 
 * @author Leandro Carlos Rodrigues <leandro@allchemistry.com.br>
 */
public final class SubnetIPv4 extends Subnet implements Comparable<SubnetIPv4> {
    
    private static final long serialVersionUID = 1L;
    
    private final int address; // Primeiro endereço do bloco.
    private final int mask; // Máscara da subrede.
    
    /**
     * Construtor do blocos de países.
     * @param inetnum o endereçamento CIDR do bloco.
     * @param server o server que possui as informações daquele bloco.
     */
    protected SubnetIPv4(String inetnum, String server) {
        super(inetnum = correctCIDR(inetnum), server);
        // Endereçamento do bloco.
        this.mask = getMaskNet(inetnum);
        this.address = getAddressNet(inetnum) & mask; // utiliza a máscara para garantir que o endereço passado seja o primeiro endereço do bloco.
    }
    
    /**
     * Retorna o primeiro endereço do bloco em inteiro de 32 bits.
     * @return o primeiro endereço do bloco em inteiro de 32 bits.
     */
    public int getFirstAddress() {
        return address;
    }
    
    /**
     * Retorna o último endereço do bloco em inteiro de 32 bits.
     * @return o último endereço do bloco em inteiro de 32 bits.
     */
    public int getLastAddress() {
        return address | ~mask;
    }
    
    /**
     * Construtor do blocos de alocados para ASs.
     * @param result o resultado WHOIS do bloco.
     * @throws QueryException se houver alguma falha da atualização do registro.
     */
    private SubnetIPv4(String result) throws ProcessException {
        super(result);
        // Endereçamento do bloco.
        this.mask = getMaskNet(getInetnum());
        this.address = getAddressNet(getInetnum()) & mask; // utiliza a máscara para garantir que o endereço passado seja o primeiro endereço do bloco.
    }
    
    @Override
    protected boolean refresh() throws ProcessException {
        boolean isInetnum = super.refresh();
        // Atualiza flag de atualização.
        SUBNET_CHANGED = true;
        return isInetnum;
    }
    
    /**
     * Corrige o endereço da notação CIDR para sem abreviação.
     * @param inetnum o endereço com notação CIDR sem abreviação.
     * @return o endereço da notação CIDR sem abreviação.
     */
    private static String correctCIDR(String inetnum) {
        int index = inetnum.indexOf('/');
        String ip = inetnum.substring(0, index);
        String mask = inetnum.substring(index+1);
        ArrayList<String> ipSequence = new ArrayList<String>(4);
        StringTokenizer tokenizer = new StringTokenizer(ip, ".");
        while (tokenizer.hasMoreTokens()) {
            ipSequence.add(tokenizer.nextToken());
        }
        while (ipSequence.size() < 4) {
            ipSequence.add("0");
        }
        return ipSequence.get(0) + "." +
                ipSequence.get(1) + "." +
                ipSequence.get(2) + "." + 
                ipSequence.get(3) + "/" + mask;
    }
    
    /**
     * Retorna o endereço IP em inteiro de 32 bits da notação CIDR.
     * @param inetnum endereço de bloco em notação CIDR.
     * @return o endereço IP em inteiro de 32 bits da notação CIDR.
     */
    public static int getAddressNet(String inetnum) {
        int index = inetnum.indexOf('/');
        String ip = inetnum.substring(0, index);
        return getAddressIP(ip);
    }
    
    public static byte[] split(String ip) {
        byte[] address = new byte[4];
        StringTokenizer tokenizer = new StringTokenizer(ip, ".");
        for (int i = 0; i < 4; i++) {
            if (tokenizer.hasMoreTokens()) {
                address[i] |= Short.parseShort(tokenizer.nextToken());
            }
        }
        return address;
    }
    
    public static String reverse(String ip) {
        byte[] splitedIP = SubnetIPv4.split(ip);
        int octet1 = splitedIP[0] & 0xFF;
        int octet2 = splitedIP[1] & 0xFF;
        int octet3 = splitedIP[2] & 0xFF;
        int octet4 = splitedIP[3] & 0xFF;
        return octet4 + "." + octet3 + "." + octet2 + "." + octet1;
    }
    
    /**
     * Meio mais seguro de padronizar os endereços IP.
     * @param ip o endereço IPv4.
     * @return o endereço IPv4 padronizado.
     */
    public static String correctIP(String ip) {
        byte[] splitedIP = split(ip);
        int octet1 = splitedIP[0] & 0xFF;
        int octet2 = splitedIP[1] & 0xFF;
        int octet3 = splitedIP[2] & 0xFF;
        int octet4 = splitedIP[3] & 0xFF;
        return octet1 + "." + octet2 + "." + octet3 + "." + octet4;
    }
    
    /**
     * Retorna o endereço IP em inteiro de 32 bits da notação IP.
     * @param ip endereço de IP em notação IP.
     * @return o endereço IP em inteiro de 32 bits da notação IPv4.
     */
    public static int getAddressIP(String ip) {
        int address = 0;
        int i = 0;
        for (byte octeto : split(ip)) {
            address += (int) octeto & 0xFF;
            if (i++ < 3) {
                address <<= 8;
            }
        }
        return address;
    }
    
    /**
     * Retorna a máscara em inteiro de 32 bits da notação CIDR.
     * @param inetnum endereço de bloco em notação CIDR.
     * @return a máscara em inteiro de 32 bits da notação CIDR.
     */
    public static int getMaskNet(String inetnum) {
        int index = inetnum.indexOf('/');
        int mask = Integer.parseInt(inetnum.substring(index+1));
        return 0xFFFFFFFF << 32 - mask;
    }
    
    /**
     * Verifica se um IP é válido na notação de IP.
     * @param ip o IP a ser verificado.
     * @return verdadeiro se um IP é válido na notação de IPv4.
     */
    public static boolean isValidIPv4(String ip) {
        if (ip == null) {
            return false;
        } else {
            ip = ip.trim();
            return Pattern.matches("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}"
                    + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", ip);
        }
    }
    
    /**
     * Verifica se um CIDR é válido na notação de IPv4.
     * @param cidr o CIDR a ser verificado.
     * @return verdadeiro se um CIDR é válido na notação de IPv4.
     */
    public static boolean isValidCIDRv4(String cidr) {
        cidr = cidr.trim();
        return Pattern.matches("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}"
                + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])/[0-9]{1,2}$", cidr);
    }
    
    /**
     * Mapa de blocos IP de ASs com busca em árvore binária log2(n).
     */
    private static final TreeMap<Integer,SubnetIPv4> SUBNET_MAP = new TreeMap<Integer,SubnetIPv4>();
    
    /**
     * Adciiona o registro de bloco de IP no cache.
     * @param subnet o de bloco de IP que deve ser adicionado.
     */
    private static synchronized void addSubnet(SubnetIPv4 subnet) {
        SUBNET_MAP.put(subnet.address, subnet);
        // Atualiza flag de atualização.
        SUBNET_CHANGED = true;
    }
    
    /**
     * Remove o registro de bloco de IP do cache.
     * @param subnet o de bloco de IP que deve ser removido.
     */
    private static synchronized void removeSubnet(SubnetIPv4 subnet) {
        if (SUBNET_MAP.remove(subnet.address) != null) {
            // Atualiza flag de atualização.
            SUBNET_CHANGED = true;
        }
    }
    
    /**
     * Remove registro de bloco de IP para AS do cache.
     * @param ip o IP cujo bloco deve ser removido.
     * @return o registro de bloco removido, se existir.
     */
    public static synchronized SubnetIPv4 removeSubnet(String ip) {
        int address = getAddressIP(ip.trim()); // Implementar validação.
        // Busca eficiente O(log2(n)).
        // Este método só funciona se o mapa não tiver intersecção de blocos.
        Integer key = SUBNET_MAP.floorKey(address);
        if (key == null && !SUBNET_MAP.isEmpty()) {
            // Devido à limitação do Java em não traballhar com unsigned int,
            // fazer uma consulta circular pelo último bloco do mapa.
            key = SUBNET_MAP.lastKey();
        }
        if (key == null) {
            return null;
        } else {
            SubnetIPv4 subnet = SUBNET_MAP.remove(key);
            // Atualiza flag de atualização.
            SUBNET_CHANGED = true;
            return subnet;
        }
    }
    
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean SUBNET_CHANGED = false;
    
    protected static synchronized TreeSet<Subnet> getSubnetSet() {
        TreeSet<Subnet> subnetSet = new TreeSet<Subnet>();
        subnetSet.addAll(SUBNET_MAP.values());
        return subnetSet;
    }
    
    /**
     * Atualiza o bloco de IP de AS de um determinado IP.
     * @param ip o IP cujo bloco deve ser retornado.
     * @throws ProcessException se houver falha no processamento.
     */
    public static void refreshSubnet(String ip) throws ProcessException {
        int address = getAddressIP(ip.trim()); // Implementar validação.
        // Busca eficiente O(log2(n)).
        // Este método só funciona se o mapa não tiver intersecção de blocos.
        Integer key = SUBNET_MAP.floorKey(address);
        if (key == null && !SUBNET_MAP.isEmpty()) {
            // Devido à limitação do Java em não traballhar com unsigned int,
            // fazer uma consulta circular pelo último bloco do mapa.
            key = SUBNET_MAP.lastKey();
        }
        if (key != null) {
            // Encontrou uma subrede com endereço inicial imediatemente inferior.
            SubnetIPv4 subnet = SUBNET_MAP.get(key);
            // Verifica se o ip pertence à subrede encontrada.
            if (subnet.contains(address)) {
                // Atualizando campos do registro.
                if (!subnet.refresh()) {
                    // Domínio real do resultado WHOIS não bate com o registro.
                    // Pode haver mudança na distribuição dos blocos.
                    // Apagando registro de bloco do cache.
                    removeSubnet(subnet);
                    // Segue para nova consulta.
                }
            }
        }
        // Não encontrou a sub-rede em cache.
        // Selecionando servidor da pesquisa WHOIS.
        String server = getWhoisServer(address);
        // Fazer a consulta no WHOIS.
        String result = Server.whois(ip, server);
        SubnetIPv4 subnet = new SubnetIPv4(result);
        subnet.server = server; // Temporário até final de transição.
        addSubnet(subnet);
    }
    
    public static String getOwnerID(String ip) {
        try {
            SubnetIPv4 subnet = getSubnet(ip);
            return subnet.get("ownerid", false);
        } catch (ProcessException ex) {
            if (ex.getMessage().equals("ERROR: SERVER NOT FOUND")) {
                return null;
            } else if (ex.getMessage().equals("ERROR: WHOIS QUERY LIMIT")) {
                return null;
            } else {
                Server.logError(ex);
                return null;
            }
        }
    }
    
    public static String getOwnerC(String ip) {
        try {
            SubnetIPv4 subnet = getSubnet(ip);
            return subnet.get("owner-c", false);
        } catch (ProcessException ex) {
            if (ex.getMessage().equals("ERROR: SERVER NOT FOUND")) {
                return null;
            } else {
                Server.logError(ex);
                return null;
            }
        }
    }
    
    /**
     * Retorna o bloco de IP de AS de um determinado IP.
     * @param ip o IP cujo bloco deve ser retornado.
     * @return o registro de bloco IPv4 de AS de um determinado IP.
     * @throws ProcessException se houver falha no processamento.
     */
    public static SubnetIPv4 getSubnet(String ip) throws ProcessException {
        int address = getAddressIP(ip.trim()); // Implementar validação.
        // Busca eficiente O(log2(n)).
        // Este método só funciona se o mapa não tiver intersecção de blocos.
        Integer key = SUBNET_MAP.floorKey(address);
        if (key == null && !SUBNET_MAP.isEmpty()) {
            // Devido à limitação do Java em não traballhar com unsigned int,
            // fazer uma consulta circular pelo último bloco do mapa.
            key = SUBNET_MAP.lastKey();
        }
        if (key != null) {
            // Encontrou uma subrede com endereço inicial imediatemente inferior.
            SubnetIPv4 subnet = SUBNET_MAP.get(key);
            // Verifica se o ip pertence à subrede encontrada.
            if (subnet.contains(address)) {
                if (subnet.isRegistryExpired()) {
                    // Registro expirado.
                    // Atualizando campos do registro.
                    if (subnet.refresh()) {
                        // Bloco do resultado WHOIS bate com o bloco do registro.
                        return subnet;
                    } else {
                        // Domínio real do resultado WHOIS não bate com o registro.
                        // Pode haver mudança na distribuição dos blocos.
                        // Apagando registro de bloco do cache.
                        removeSubnet(subnet);
                        // Segue para nova consulta.
                    }
//                } else if (subnet.isRegistryAlmostExpired() || subnet.isReduced()) {
//                    // Registro quase vencendo ou com informação reduzida.
//                    // Adicionar no conjunto para atualização em background.
//                    SUBNET_REFRESH.add(subnet);
//                    return subnet;
                } else {
                    return subnet;
                }
            }
        }
        // Não encontrou a sub-rede em cache.
        // Selecionando servidor da pesquisa WHOIS.
        String server = getWhoisServer(address);
        // Fazer a consulta no WHOIS.
        String result = Server.whois(ip, server);
        SubnetIPv4 subnet = new SubnetIPv4(result);
        subnet.server = server; // Temporário até final de transição.
        addSubnet(subnet);
        return subnet;
    }
    
    /**
     * Armazenamento de cache em disco.
     */
    public static synchronized void store() {
        if (SUBNET_CHANGED) {
            try {
                long time = System.currentTimeMillis();
                File file = new File("subnet4.map");
                FileOutputStream outputStream = new FileOutputStream(file);
                try {
                    SerializationUtils.serialize(SUBNET_MAP, outputStream);
                    // Atualiza flag de atualização.
                    SUBNET_CHANGED = false;
                } finally {
                    outputStream.close();
                }
                Server.logStore(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    /**
     * Carregamento de cache do disco.
     */
    public static synchronized void load() {
        long time = System.currentTimeMillis();
        File file = new File("subnet4.map");
        if (file.exists()) {
            try {
                TreeMap<Integer, SubnetIPv4> map;
                FileInputStream fileInputStream = new FileInputStream(file);
                try {
                    map = SerializationUtils.deserialize(fileInputStream);
                } finally {
                    fileInputStream.close();
                }
                SUBNET_MAP.putAll(map);
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    /**
     * Verifica se o endereço IP passado faz parte do bloco.
     * @param ip o endereço IP em notação IPv4.
     * @return verdadeiro se o endereço IP passado faz parte do bloco.
     */
    public boolean contains(String ip) {
        return contains(getAddressIP(ip));
    }
    
    /**
     * Verifica se o endereço IP passado faz parte do bloco.
     * @param ip o endereço IP em inteiro de 32 bits.
     * @return verdadeiro se o endereço IP passado faz parte do bloco.
     */
    public boolean contains(int ip) {
        return this.address == (ip & mask);
    }
    
    @Override
    public int compareTo(SubnetIPv4 other) {
        return new Integer(this.address).compareTo(other.address);
    }
    
    /**
     * Mapa completo dos blocos alocados aos países.
     */
    private static final TreeMap<Integer,SubnetIPv4> SERVER_MAP = new TreeMap<Integer,SubnetIPv4>();
    
    /**
     * Adiciona um servidor WHOIS na lista com seu respecitivo bloco.
     * @param inetnum o endereço de bloco em notação CIDR.
     * @param server o servidor WHOIS responsável por aquele bloco.
     */
    private static void addServer(String inetnum, String server) {
        try {
            SubnetIPv4 subnet = new SubnetIPv4(inetnum, server);
            SERVER_MAP.put(subnet.address, subnet);
        } catch (Exception ex) {
            Server.logError(ex);
        }
    }
    
    // Temporário
    @Override
    public String getWhoisServer() throws ProcessException {
        return getWhoisServer(address);
    }
    
    /**
     * Retorna o servidor que possui a informação de bloco IPv4 de AS de um IP.
     * @param address endereço IP em inteiro de 32 bits.
     * @return o servidor que possui a informação de bloco IPv4 de AS de um IP.
     * @throws QueryException se o bloco não for encontrado para o IP especificado.
     */
    private static String getWhoisServer(int address) throws ProcessException {
        // Busca eficiente O(log2(n)).
        // Este método só funciona se o mapa não tiver intersecção de blocos.
        Integer key = SERVER_MAP.floorKey(address);
        if (key == null && !SERVER_MAP.isEmpty()) {
            key = SERVER_MAP.lastKey();
        }
        if (key == null) {
            throw new ProcessException("ERROR: SERVER NOT FOUND");
        } else {
            SubnetIPv4 subnet = SERVER_MAP.get(key);
            if (subnet.contains(address)) {
                return subnet.getServer();
            } else {
                throw new ProcessException("ERROR: SERVER NOT FOUND");
            }
        }
    }
    
    /**
     * Construção do mapa dos blocos alocados.
     * Temporário até implementação de busca pelo whois.iana.org.
     */
    static {
        addServer("139.82.0.0/16", Server.WHOIS_BR);
        addServer("143.54.0.0/16", Server.WHOIS_BR);
        addServer("143.106.0.0/16", Server.WHOIS_BR);
        addServer("143.107.0.0/16", Server.WHOIS_BR);
        addServer("143.108.0.0/16", Server.WHOIS_BR);
        addServer("144.23.0.0/16", Server.WHOIS_BR);
        addServer("146.134.0.0/16", Server.WHOIS_BR);
        addServer("146.164.0.0/16", Server.WHOIS_BR);
        addServer("147.65.0.0/16", Server.WHOIS_BR);
        addServer("150.161.0.0/16", Server.WHOIS_BR);
        addServer("150.162.0.0/16", Server.WHOIS_BR);
        addServer("150.163.0.0/16", Server.WHOIS_BR);
        addServer("150.164.0.0/16", Server.WHOIS_BR);
        addServer("150.165.0.0/16", Server.WHOIS_BR);
        addServer("152.84.0.0/16", Server.WHOIS_BR);
        addServer("152.92.0.0/16", Server.WHOIS_BR);
        addServer("155.211.0.0/16", Server.WHOIS_BR);
        addServer("157.86.0.0/16", Server.WHOIS_BR);
        addServer("161.24.0.0/16", Server.WHOIS_BR);
        addServer("161.79.0.0/16", Server.WHOIS_BR);
        addServer("161.148.0.0/16", Server.WHOIS_BR);
        addServer("164.41.0.0/16", Server.WHOIS_BR);
        addServer("164.85.0.0/16", Server.WHOIS_BR);
        addServer("170.66.0.0/16", Server.WHOIS_BR);
        addServer("189.0.0.0/11", Server.WHOIS_BR);
        addServer("189.32.0.0/11", Server.WHOIS_BR);
        addServer("189.64.0.0/11", Server.WHOIS_BR);
        addServer("189.96.0.0/11", Server.WHOIS_BR);
        addServer("192.80.209.0/24", Server.WHOIS_BR);
        addServer("192.111.229.0/24", Server.WHOIS_BR);
        addServer("192.111.230.0/24", Server.WHOIS_BR);
        addServer("192.132.35.0/24", Server.WHOIS_BR);
        addServer("192.146.157.0/24", Server.WHOIS_BR);
        addServer("192.146.229.0/24", Server.WHOIS_BR);
        addServer("192.147.210.0/24", Server.WHOIS_BR);
        addServer("192.147.218.0/24", Server.WHOIS_BR);
        addServer("192.153.88.0/24", Server.WHOIS_BR);
        addServer("192.153.120.0/24", Server.WHOIS_BR);
        addServer("192.153.155.0/24", Server.WHOIS_BR);
        addServer("192.159.116.0/24", Server.WHOIS_BR);
        addServer("192.159.117.0/24", Server.WHOIS_BR);
        addServer("192.160.45.0/24", Server.WHOIS_BR);
        addServer("192.160.50.0/24", Server.WHOIS_BR);
        addServer("192.160.111.0/24", Server.WHOIS_BR);
        addServer("192.160.128.0/24", Server.WHOIS_BR);
        addServer("192.160.188.0/24", Server.WHOIS_BR);
        addServer("192.188.11.0/24", Server.WHOIS_BR);
        addServer("192.190.30.0/24", Server.WHOIS_BR);
        addServer("192.190.31.0/24", Server.WHOIS_BR);
        addServer("192.195.237.0/24", Server.WHOIS_BR);
        addServer("192.198.8.0/21", Server.WHOIS_BR);
        addServer("192.207.194.0/24", Server.WHOIS_BR);
        addServer("192.207.195.0/24", Server.WHOIS_BR);
        addServer("192.207.200.0/24", Server.WHOIS_BR);
        addServer("192.207.201.0/24", Server.WHOIS_BR);
        addServer("192.207.202.0/24", Server.WHOIS_BR);
        addServer("192.207.203.0/24", Server.WHOIS_BR);
        addServer("192.207.204.0/24", Server.WHOIS_BR);
        addServer("192.207.205.0/24", Server.WHOIS_BR);
        addServer("192.207.206.0/24", Server.WHOIS_BR);
        addServer("192.223.64.0/18", Server.WHOIS_BR);
        addServer("192.231.114.0/23", Server.WHOIS_BR);
        addServer("192.231.116.0/22", Server.WHOIS_BR);
        addServer("192.231.120.0/23", Server.WHOIS_BR);
        addServer("192.231.175.0/24", Server.WHOIS_BR);
        addServer("192.231.176.0/24", Server.WHOIS_BR);
        addServer("198.12.32.0/19", Server.WHOIS_BR);
        addServer("198.17.120.0/23", Server.WHOIS_BR);
        addServer("198.17.231.0/24", Server.WHOIS_BR);
        addServer("198.17.232.0/24", Server.WHOIS_BR);
        addServer("198.49.128.0/22", Server.WHOIS_BR);
        addServer("198.49.132.0/23", Server.WHOIS_BR);
        addServer("198.50.16.0/21", Server.WHOIS_BR);
        addServer("198.58.8.0/22", Server.WHOIS_BR);
        addServer("198.58.12.0/24", Server.WHOIS_BR);
        addServer("198.184.161.0/24", Server.WHOIS_BR);
        addServer("200.0.8.0/21", Server.WHOIS_BR);
        addServer("200.0.32.0/20", Server.WHOIS_BR);
        addServer("200.0.48.0/21", Server.WHOIS_BR);
        addServer("200.0.56.0/22", Server.WHOIS_BR);
        addServer("200.0.60.0/23", Server.WHOIS_BR);
        addServer("200.0.67.0/24", Server.WHOIS_BR);
        addServer("200.0.68.0/24", Server.WHOIS_BR);
        addServer("200.0.69.0/24", Server.WHOIS_BR);
        addServer("200.0.70.0/24", Server.WHOIS_BR);
        addServer("200.0.71.0/24", Server.WHOIS_BR);
        addServer("200.0.72.0/24", Server.WHOIS_BR);
        addServer("200.0.81.0/24", Server.WHOIS_BR);
        addServer("200.0.85.0/24", Server.WHOIS_BR);
        addServer("200.0.86.0/24", Server.WHOIS_BR);
        addServer("200.0.87.0/24", Server.WHOIS_BR);
        addServer("200.0.89.0/24", Server.WHOIS_BR);
        addServer("200.0.90.0/23", Server.WHOIS_BR);
        addServer("200.0.92.0/24", Server.WHOIS_BR);
        addServer("200.0.93.0/24", Server.WHOIS_BR);
        addServer("200.0.100.0/23", Server.WHOIS_BR);
        addServer("200.0.102.0/24", Server.WHOIS_BR);
        addServer("200.0.114.0/24", Server.WHOIS_BR);
        addServer("200.3.16.0/20", Server.WHOIS_BR);
        addServer("200.5.9.0/24", Server.WHOIS_BR);
        addServer("200.6.35.0/24", Server.WHOIS_BR);
        addServer("200.6.36.0/23", Server.WHOIS_BR);
        addServer("200.6.38.0/24", Server.WHOIS_BR);
        addServer("200.6.39.0/24", Server.WHOIS_BR);
        addServer("200.6.40.0/24", Server.WHOIS_BR);
        addServer("200.6.41.0/24", Server.WHOIS_BR);
        addServer("200.6.42.0/24", Server.WHOIS_BR);
        addServer("200.6.43.0/24", Server.WHOIS_BR);
        addServer("200.6.44.0/24", Server.WHOIS_BR);
        addServer("200.6.45.0/24", Server.WHOIS_BR);
        addServer("200.6.46.0/24", Server.WHOIS_BR);
        addServer("200.6.47.0/24", Server.WHOIS_BR);
        addServer("200.6.48.0/24", Server.WHOIS_BR);
        addServer("200.6.128.0/22", Server.WHOIS_BR);
        addServer("200.6.132.0/23", Server.WHOIS_BR);
        addServer("200.7.0.0/22", Server.WHOIS_BR);
        addServer("200.7.8.0/23", Server.WHOIS_BR);
        addServer("200.7.10.0/23", Server.WHOIS_BR);
        addServer("200.7.12.0/24", Server.WHOIS_BR);
        addServer("200.7.13.0/24", Server.WHOIS_BR);
        addServer("200.9.0.0/23", Server.WHOIS_BR);
        addServer("200.9.2.0/24", Server.WHOIS_BR);
        addServer("200.9.65.0/24", Server.WHOIS_BR);
        addServer("200.9.66.0/24", Server.WHOIS_BR);
        addServer("200.9.67.0/24", Server.WHOIS_BR);
        addServer("200.9.68.0/24", Server.WHOIS_BR);
        addServer("200.9.69.0/24", Server.WHOIS_BR);
        addServer("200.9.70.0/24", Server.WHOIS_BR);
        addServer("200.9.71.0/24", Server.WHOIS_BR);
        addServer("200.9.76.0/24", Server.WHOIS_BR);
        addServer("200.9.77.0/24", Server.WHOIS_BR);
        addServer("200.9.84.0/24", Server.WHOIS_BR);
        addServer("200.9.85.0/24", Server.WHOIS_BR);
        addServer("200.9.86.0/24", Server.WHOIS_BR);
        addServer("200.9.87.0/24", Server.WHOIS_BR);
        addServer("200.9.88.0/24", Server.WHOIS_BR);
        addServer("200.9.89.0/24", Server.WHOIS_BR);
        addServer("200.9.90.0/23", Server.WHOIS_BR);
        addServer("200.9.92.0/24", Server.WHOIS_BR);
        addServer("200.9.93.0/24", Server.WHOIS_BR);
        addServer("200.9.94.0/24", Server.WHOIS_BR);
        addServer("200.9.95.0/24", Server.WHOIS_BR);
        addServer("200.9.102.0/24", Server.WHOIS_BR);
        addServer("200.9.103.0/24", Server.WHOIS_BR);
        addServer("200.9.104.0/24", Server.WHOIS_BR);
        addServer("200.9.105.0/24", Server.WHOIS_BR);
        addServer("200.9.106.0/24", Server.WHOIS_BR);
        addServer("200.9.107.0/24", Server.WHOIS_BR);
        addServer("200.9.112.0/24", Server.WHOIS_BR);
        addServer("200.9.113.0/24", Server.WHOIS_BR);
        addServer("200.9.114.0/24", Server.WHOIS_BR);
        addServer("200.9.116.0/24", Server.WHOIS_BR);
        addServer("200.9.117.0/24", Server.WHOIS_BR);
        addServer("200.9.118.0/23", Server.WHOIS_BR);
        addServer("200.9.120.0/24", Server.WHOIS_BR);
        addServer("200.9.121.0/24", Server.WHOIS_BR);
        addServer("200.9.123.0/24", Server.WHOIS_BR);
        addServer("200.9.124.0/24", Server.WHOIS_BR);
        addServer("200.9.125.0/24", Server.WHOIS_BR);
        addServer("200.9.126.0/24", Server.WHOIS_BR);
        addServer("200.9.127.0/24", Server.WHOIS_BR);
        addServer("200.9.129.0/24", Server.WHOIS_BR);
        addServer("200.9.130.0/24", Server.WHOIS_BR);
        addServer("200.9.131.0/24", Server.WHOIS_BR);
        addServer("200.9.132.0/24", Server.WHOIS_BR);
        addServer("200.9.133.0/24", Server.WHOIS_BR);
        addServer("200.9.134.0/24", Server.WHOIS_BR);
        addServer("200.9.135.0/24", Server.WHOIS_BR);
        addServer("200.9.136.0/23", Server.WHOIS_BR);
        addServer("200.9.138.0/24", Server.WHOIS_BR);
        addServer("200.9.139.0/24", Server.WHOIS_BR);
        addServer("200.9.140.0/24", Server.WHOIS_BR);
        addServer("200.9.143.0/24", Server.WHOIS_BR);
        addServer("200.9.144.0/24", Server.WHOIS_BR);
        addServer("200.9.148.0/24", Server.WHOIS_BR);
        addServer("200.9.149.0/24", Server.WHOIS_BR);
        addServer("200.9.158.0/23", Server.WHOIS_BR);
        addServer("200.9.160.0/22", Server.WHOIS_BR);
        addServer("200.9.164.0/24", Server.WHOIS_BR);
        addServer("200.9.169.0/24", Server.WHOIS_BR);
        addServer("200.9.170.0/23", Server.WHOIS_BR);
        addServer("200.9.172.0/23", Server.WHOIS_BR);
        addServer("200.9.174.0/24", Server.WHOIS_BR);
        addServer("200.9.175.0/24", Server.WHOIS_BR);
        addServer("200.9.181.0/24", Server.WHOIS_BR);
        addServer("200.9.182.0/24", Server.WHOIS_BR);
        addServer("200.9.183.0/24", Server.WHOIS_BR);
        addServer("200.9.184.0/24", Server.WHOIS_BR);
        addServer("200.9.185.0/24", Server.WHOIS_BR);
        addServer("200.9.186.0/24", Server.WHOIS_BR);
        addServer("200.9.199.0/24", Server.WHOIS_BR);
        addServer("200.9.200.0/24", Server.WHOIS_BR);
        addServer("200.9.202.0/24", Server.WHOIS_BR);
        addServer("200.9.203.0/24", Server.WHOIS_BR);
        addServer("200.9.206.0/24", Server.WHOIS_BR);
        addServer("200.9.207.0/24", Server.WHOIS_BR);
        addServer("200.9.214.0/24", Server.WHOIS_BR);
        addServer("200.9.220.0/22", Server.WHOIS_BR);
        addServer("200.9.224.0/24", Server.WHOIS_BR);
        addServer("200.9.226.0/24", Server.WHOIS_BR);
        addServer("200.9.229.0/24", Server.WHOIS_BR);
        addServer("200.9.234.0/24", Server.WHOIS_BR);
        addServer("200.9.249.0/24", Server.WHOIS_BR);
        addServer("200.9.250.0/23", Server.WHOIS_BR);
        addServer("200.9.252.0/24", Server.WHOIS_BR);
        addServer("200.10.4.0/22", Server.WHOIS_BR);
        addServer("200.10.32.0/20", Server.WHOIS_BR);
        addServer("200.10.48.0/21", Server.WHOIS_BR);
        addServer("200.10.56.0/22", Server.WHOIS_BR);
        addServer("200.10.132.0/22", Server.WHOIS_BR);
        addServer("200.10.136.0/24", Server.WHOIS_BR);
        addServer("200.10.137.0/24", Server.WHOIS_BR);
        addServer("200.10.138.0/24", Server.WHOIS_BR);
        addServer("200.10.141.0/24", Server.WHOIS_BR);
        addServer("200.10.144.0/24", Server.WHOIS_BR);
        addServer("200.10.146.0/24", Server.WHOIS_BR);
        addServer("200.10.153.0/24", Server.WHOIS_BR);
        addServer("200.10.154.0/24", Server.WHOIS_BR);
        addServer("200.10.156.0/24", Server.WHOIS_BR);
        addServer("200.10.157.0/24", Server.WHOIS_BR);
        addServer("200.10.158.0/24", Server.WHOIS_BR);
        addServer("200.10.159.0/24", Server.WHOIS_BR);
        addServer("200.10.163.0/24", Server.WHOIS_BR);
        addServer("200.10.164.0/24", Server.WHOIS_BR);
        addServer("200.10.173.0/24", Server.WHOIS_BR);
        addServer("200.10.174.0/23", Server.WHOIS_BR);
        addServer("200.10.176.0/24", Server.WHOIS_BR);
        addServer("200.10.177.0/24", Server.WHOIS_BR);
        addServer("200.10.178.0/23", Server.WHOIS_BR);
        addServer("200.10.180.0/23", Server.WHOIS_BR);
        addServer("200.10.183.0/24", Server.WHOIS_BR);
        addServer("200.10.185.0/24", Server.WHOIS_BR);
        addServer("200.10.187.0/24", Server.WHOIS_BR);
        addServer("200.10.189.0/24", Server.WHOIS_BR);
        addServer("200.10.191.0/24", Server.WHOIS_BR);
        addServer("200.10.192.0/23", Server.WHOIS_BR);
        addServer("200.10.209.0/24", Server.WHOIS_BR);
        addServer("200.10.210.0/24", Server.WHOIS_BR);
        addServer("200.10.227.0/24", Server.WHOIS_BR);
        addServer("200.10.245.0/24", Server.WHOIS_BR);
        addServer("200.11.0.0/21", Server.WHOIS_BR);
        addServer("200.11.8.0/21", Server.WHOIS_BR);
        addServer("200.11.16.0/21", Server.WHOIS_BR);
        addServer("200.11.24.0/22", Server.WHOIS_BR);
        addServer("200.11.28.0/24", Server.WHOIS_BR);
        addServer("200.12.0.0/21", Server.WHOIS_BR);
        addServer("200.12.8.0/21", Server.WHOIS_BR);
        addServer("200.12.131.0/24", Server.WHOIS_BR);
        addServer("200.12.139.0/24", Server.WHOIS_BR);
        addServer("200.12.157.0/24", Server.WHOIS_BR);
        addServer("200.13.8.0/21", Server.WHOIS_BR);
        addServer("200.14.32.0/23", Server.WHOIS_BR);
        addServer("200.14.35.0/24", Server.WHOIS_BR);
        addServer("200.14.36.0/24", Server.WHOIS_BR);
        addServer("200.17.0.0/16", Server.WHOIS_BR);
        addServer("200.18.0.0/15", Server.WHOIS_BR);
        addServer("200.20.0.0/16", Server.WHOIS_BR);
        addServer("200.96.0.0/13", Server.WHOIS_BR);
        addServer("200.128.0.0/9", Server.WHOIS_BR);
        addServer("201.0.0.0/12", Server.WHOIS_BR);
        addServer("201.16.0.0/12", Server.WHOIS_BR);
        addServer("201.32.0.0/12", Server.WHOIS_BR);
        addServer("201.48.0.0/12", Server.WHOIS_BR);
        addServer("201.64.0.0/11", Server.WHOIS_BR);
        addServer("206.221.80.0/20", Server.WHOIS_BR);
    }
}
