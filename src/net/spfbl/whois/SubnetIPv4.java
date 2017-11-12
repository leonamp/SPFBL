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
package net.spfbl.whois;

import net.spfbl.core.Server;
import net.spfbl.core.ProcessException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
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
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public final class SubnetIPv4 extends Subnet {
    
    private static final long serialVersionUID = 1L;
    
    private final int address; // Primeiro endereço do bloco.
    private final int mask; // Máscara da subrede.
    
    /**
     * Construtor do blocos de países.
     * @param inetnum o endereçamento CIDR do bloco.
     * @param server o server que possui as informações daquele bloco.
     */
    protected SubnetIPv4(String inetnum, String server) {
        super(inetnum, server);
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
        CHANGED = true;
        return isInetnum;
    }
    
    public static String getFirstIPv4(String inetnum) {
        if (inetnum == null) {
            return null;
        } else {
            inetnum = normalizeCIDRv4(inetnum);
            int index = inetnum.indexOf('/');
            String ip = inetnum.substring(0, index);
            String size = inetnum.substring(index+1);
            int sizeInt = Integer.parseInt(size);
            byte[] mask = SubnetIPv4.getMaskIPv4(sizeInt);
            byte[] address = SubnetIPv4.split(ip, mask);
            int octet1 = address[0] & 0xFF;
            int octet2 = address[1] & 0xFF;
            int octet3 = address[2] & 0xFF;
            int octet4 = address[3] & 0xFF;
            return octet1 + "." + octet2 + "." + octet3 + "." + octet4;
        }
    }
    
    public static String getLastIPv4(String inetnum) {
        if (inetnum == null) {
            return null;
        } else {
            inetnum = normalizeCIDRv4(inetnum);
            int index = inetnum.indexOf('/');
            String ip = inetnum.substring(0, index);
            String size = inetnum.substring(index+1);
            int sizeInt = Integer.parseInt(size);
            byte[] mask = SubnetIPv4.getMaskIPv4(sizeInt);
            byte[] address = SubnetIPv4.split(ip, mask);
            int octet1 = (address[0] & 0xFF) ^ (~mask[0] & 0xFF);
            int octet2 = (address[1] & 0xFF) ^ (~mask[1] & 0xFF);
            int octet3 = (address[2] & 0xFF) ^ (~mask[2] & 0xFF);
            int octet4 = (address[3] & 0xFF) ^ (~mask[3] & 0xFF);
            return octet1 + "." + octet2 + "." + octet3 + "." + octet4;
        }
    }
    
    /**
     * Corrige o endereço da notação CIDR para sem abreviação.
     * @param inetnum o endereço com notação CIDR sem abreviação.
     * @return o endereço da notação CIDR sem abreviação.
     */
    public static String normalizeCIDRv4(String inetnum) {
        if (inetnum == null) {
            return null;
        } else {
            int index = inetnum.indexOf('/');
            String ip = inetnum.substring(0, index);
            String size = inetnum.substring(index+1);
            int sizeInt = Integer.parseInt(size);
            if (sizeInt < 0 || sizeInt > 32) {
                return null;
            } else {
                byte[] mask = SubnetIPv4.getMaskIPv4(sizeInt);
                byte[] address = SubnetIPv4.split(ip, mask);
                int octet1 = address[0] & 0xFF;
                int octet2 = address[1] & 0xFF;
                int octet3 = address[2] & 0xFF;
                int octet4 = address[3] & 0xFF;
                return octet1 + "." + octet2 + "." + octet3 + "." + octet4 + "/" + sizeInt;
            }
        }
    }
    
    /**
     * Retorna o endereço IP em inteiro de 32 bits da notação CIDR.
     * @param inetnum endereço de bloco em notação CIDR.
     * @return o endereço IP em inteiro de 32 bits da notação CIDR.
     */
    public static int getAddressNet(String inetnum) {
        inetnum = normalizeCIDRv4(inetnum);
        String ip = getFirstIP(inetnum);
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
    
    public static byte[] split(String ip, byte[] mask) {
        byte[] address = new byte[4];
        StringTokenizer tokenizer = new StringTokenizer(ip, ".");
        for (int i = 0; i < 4; i++) {
            if (tokenizer.hasMoreTokens()) {
                address[i] |= Short.parseShort(tokenizer.nextToken());
                address[i] &= mask[i];
            }
        }
        return address;
    }
    
    public static byte[] getMaskIPv4(int size) {
        byte[] mask = new byte[4];
        int n = size / 8;
        int r = size % 8;
        int i;
        for (i = 0; i < n; i++) {
            mask[i] = (byte) 0xFF;
        }
        if (i < mask.length && r > 0) {
            mask[i] = (byte) (0xFF << 8 - r);
        }
        return mask;
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
    public static String normalizeIPv4(String ip) {
        byte[] splitedIP = split(ip);
        int octet1 = splitedIP[0] & 0xFF;
        int octet2 = splitedIP[1] & 0xFF;
        int octet3 = splitedIP[2] & 0xFF;
        int octet4 = splitedIP[3] & 0xFF;
        return octet1 + "." + octet2 + "." + octet3 + "." + octet4;
    }
    
    public static String expandIPv4(String ip) {
        byte[] splitedIP = split(ip);
        int octet1 = splitedIP[0] & 0xFF;
        int octet2 = splitedIP[1] & 0xFF;
        int octet3 = splitedIP[2] & 0xFF;
        int octet4 = splitedIP[3] & 0xFF;
        return String.format("%3s", octet1).replace(' ', '0')
                + "." + String.format("%3s", octet2).replace(' ', '0')
                + "." + String.format("%3s", octet3).replace(' ', '0')
                + "." + String.format("%3s", octet4).replace(' ', '0');
    }
    
    public static String expandCIDRv4(String cidr) {
        int index = cidr.indexOf('/');
        String ip = cidr.substring(0, index);
        String mask = cidr.substring(index);
        ip = expandIPv4(ip);
        cidr = ip + mask;
        return cidr;
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
    
    public static long getLongIP(String ip) {
        long address = 0;
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
    
    public static String getPreviousIPv4(String ip) {
        if (ip == null) {
            return null;
        } else if (isValidIPv4(ip)) {
            int address = getAddressIP(ip);
            if (address == 0x00000000) {
                return null;
            } else {
                address--;
                int octet1 = (address >> 24 & 0xFF);
                int octet2 = (address >> 16 & 0xFF);
                int octet3 = (address >> 8 & 0xFF);
                int octet4 = (address & 0xFF);
                return octet1 + "." + octet2 + "." + octet3 + "." + octet4;
            }
        } else {
            return null;
        }
    }
    
    public static String getNextIPv4(String ip) {
        if (ip == null) {
            return null;
        } else if (isValidIPv4(ip)) {
            int address = getAddressIP(ip);
            if (address == 0xFFFFFFFF) {
                return null;
            } else {
                address++;
                int octet1 = (address >> 24 & 0xFF);
                int octet2 = (address >> 16 & 0xFF);
                int octet3 = (address >> 8 & 0xFF);
                int octet4 = (address & 0xFF);
                return octet1 + "." + octet2 + "." + octet3 + "." + octet4;
            }
        } else {
            return null;
        }
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
            return Pattern.matches("^"
                    + "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}"
                    + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
                    + "$", ip
                    );
        }
    }
    
    public static boolean isReservedIPv4(String ip) {
        if (ip == null) {
            return false;
        } else if (SubnetIPv4.containsIP("0.0.0.0/8", ip)) {
            return true;
        } else if (SubnetIPv4.containsIP("10.0.0.0/8", ip)) {
            return true;
        } else if (SubnetIPv4.containsIP("100.64.0.0/10", ip)) {
            return true;
        } else if (SubnetIPv4.containsIP("127.0.0.0/8", ip)) {
            return true;
        } else if (SubnetIPv4.containsIP("169.254.0.0/16", ip)) {
            return true;
        } else if (SubnetIPv4.containsIP("172.16.0.0/12", ip)) {
            return true;
        } else if (SubnetIPv4.containsIP("192.0.0.0/24", ip)) {
            return true;
        } else if (SubnetIPv4.containsIP("192.0.2.0/24", ip)) {
            return true;
        } else if (SubnetIPv4.containsIP("192.88.99.0/24", ip)) {
            return true;
        } else if (SubnetIPv4.containsIP("192.168.0.0/16", ip)) {
            return true;
        } else if (SubnetIPv4.containsIP("198.18.0.0/15", ip)) {
            return true;
        } else if (SubnetIPv4.containsIP("198.51.100.0/24", ip)) {
            return true;
        } else if (SubnetIPv4.containsIP("203.0.113.0/24", ip)) {
            return true;
        } else if (SubnetIPv4.containsIP("224.0.0.0/4", ip)) {
            return true;
        } else if (SubnetIPv4.containsIP("240.0.0.0/4", ip)) {
            return true;
        } else if (SubnetIPv4.containsIP("255.255.255.255/32", ip)) {
            return true;
        } else {
            return false;
        }
    }
    
    public static String reverseToIPv4(String reverse) {
        byte[] address = SubnetIPv4.split(reverse);
        byte octeto = address[0];
        String ip = Integer.toString((int) octeto & 0xFF);
        for (int i = 1; i < address.length; i++) {
            octeto = address[i];
            ip = ((int) octeto & 0xFF) + "." + ip;
        }
        return SubnetIPv4.normalizeIPv4(ip);
    }
    
    /**
     * Verifica se um CIDR é válido na notação de IPv4.
     * @param cidr o CIDR a ser verificado.
     * @return verdadeiro se um CIDR é válido na notação de IPv4.
     */
    public static boolean isValidCIDRv4(String cidr) {
        if (cidr == null) {
            return false;
        } else {
            cidr = cidr.trim();
            return Pattern.matches("^"
                    + "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]){1,3}\\.){1,3}"
                    + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])/[0-9]{1,2}"
                    + "$", cidr
                    );
        }
    }
    
    /**
     * Mapa de blocos IP de ASs com busca em árvore binária log2(n).
     */
    private static final TreeMap<Long,SubnetIPv4> MAP = new TreeMap<Long,SubnetIPv4>();
    
    @Override
    public synchronized SubnetIPv4 drop() {
        return MAP.remove((long) address);
    }
    
    /**
     * Remove registro de bloco de IP para AS do cache.
     * @param ip o IP cujo bloco deve ser removido.
     * @return o registro de bloco removido, se existir.
     */
    public static synchronized SubnetIPv4 removeSubnet(String ip) {
        // Busca eficiente O(log2(n)).
        // Este método só funciona se o mapa não tiver intersecção de blocos.
        Long key = getLongIP(ip);
        key = MAP.floorKey(key);
        if (key == null) {
            return null;
        } else {
            SubnetIPv4 subnet = MAP.remove(key);
            // Atualiza flag de atualização.
            CHANGED = true;
            return subnet;
        }
    }
    
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean CHANGED = false;
    
    protected static synchronized TreeSet<Subnet> getSubnetSet() {
        TreeSet<Subnet> subnetSet = new TreeSet<Subnet>();
        subnetSet.addAll(MAP.values());
        return subnetSet;
    }
    
    /**
     * Atualiza o bloco de IP de AS de um determinado IP.
     * @param ip o IP cujo bloco deve ser retornado.
     * @throws ProcessException se houver falha no processamento.
     */
    public static synchronized void refreshSubnet(String ip) throws ProcessException {
        SubnetIPv4 subnet;
        Long key = getLongIP(ip);
        key = MAP.floorKey(key);
        while (key != null) {
            subnet = MAP.get(key);
            if (subnet.contains(ip)) {
                // Atualizando campos do registro.
                if (!subnet.refresh()) {
                    // Domínio real do resultado WHOIS não bate com o registro.
                    // Pode haver mudança na distribuição dos blocos.
                    // Apagando registro de bloco do cache.
                    MAP.remove(key);
                    CHANGED = true;
                    // Segue para nova consulta.
                    break;
                }
            } else {
                key = MAP.lowerKey(key);
            }
        }
        // Não encontrou a sub-rede em cache.
        // Selecionando servidor da pesquisa WHOIS.
        String server = getWhoisServer(ip);
        // Fazer a consulta no WHOIS.
        String result = Server.whois(ip, server);
        subnet = new SubnetIPv4(result);
        subnet.server = server; // Temporário até final de transição.
        ip = getFirstIPv4(subnet.getInetnum());
        key = getLongIP(ip);
        MAP.put(key, subnet);
        CHANGED = true;
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
            } else if (ex.getMessage().equals("ERROR: SUBNET NOT FOUND")) {
                return null;
            } else if (ex.getMessage().equals("ERROR: WHOIS QUERY LIMIT")) {
                return null;
            } else {
                Server.logError(ex);
                return null;
            }
        }
    }
    
    public static String getInetnum(String ip) {
        try {
            SubnetIPv4 subnet = getSubnet(ip);
            return normalizeCIDRv4(subnet.get("inetnum", false));
        } catch (ProcessException ex) {
            if (ex.getMessage().equals("ERROR: SERVER NOT FOUND")) {
                return null;
            } else if (ex.getMessage().equals("ERROR: WHOIS QUERY LIMIT")) {
                return null;
            } else if (ex.getMessage().equals("ERROR: SUBNET NOT FOUND")) {
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
            } else if (ex.getMessage().equals("ERROR: WHOIS QUERY LIMIT")) {
                return null;
            } else if (ex.getMessage().equals("ERROR: SUBNET NOT FOUND")) {
                return null;
            } else if (ex.getMessage().equals("ERROR: WHOIS QUERY LIMIT")) {
                return null;
            } else {
                Server.logError(ex);
                return null;
            }
        }
    }
    
    private static synchronized SubnetIPv4 newSubnet(String ip) throws ProcessException {
//        Server.logTrace("quering new WHOIS IPv4");
        // Selecionando servidor da pesquisa WHOIS.
        String server = getWhoisServer(ip);
        // Fazer a consulta no WHOIS.
        String result = Server.whois(ip, server);
        SubnetIPv4 subnet = new SubnetIPv4(result);
        subnet.server = server; // Temporário até final de transição.
        ip = getFirstIPv4(subnet.getInetnum());
        Long key = getLongIP(ip);
        MAP.put(key, subnet);
        CHANGED = true;
        return subnet;
    }
    
    /**
     * Retorna o bloco de IP de AS de um determinado IP.
     * @param ip o IP cujo bloco deve ser retornado.
     * @return o registro de bloco IPv4 de AS de um determinado IP.
     * @throws ProcessException se houver falha no processamento.
     */
    public static SubnetIPv4 getSubnet(String ip) throws ProcessException {
        SubnetIPv4 subnet;
        Long key = getLongIP(ip);
        key = MAP.floorKey(key);
        while (key != null) {
            subnet = MAP.get(key);
            if (subnet.contains(ip)) {
                if (subnet.isRegistryExpired()) {
                    // Registro expirado.
                    // Atualizando campos do registro.
                    if (subnet.refresh()) {
                        // Bloco do resultado WHOIS bate com o bloco do registro.
                        return subnet;
                    } else if (MAP.remove(key) != null) {
                        // Domínio real do resultado WHOIS não bate com o registro.
                        // Pode haver mudança na distribuição dos blocos.
                        // Apagando registro de bloco do cache.
                        CHANGED = true;
                        // Segue para nova consulta.
                        break;
                    }
                } else {
                    return subnet;
                }
            } else {
                key = MAP.lowerKey(key);
            }
        }
        // Não encontrou a sub-rede em cache.
        return newSubnet(ip);
    }
    
    private static synchronized TreeMap<Long,SubnetIPv4> getMap() {
        TreeMap<Long,SubnetIPv4> map = new TreeMap<Long,SubnetIPv4>();
        map.putAll(MAP);
        return map;
    }
    
    /**
     * Armazenamento de cache em disco.
     */
    public static void store() {
        if (CHANGED) {
            try {
//                Server.logTrace("storing subnet4.map");
                long time = System.currentTimeMillis();
                TreeMap<Long,SubnetIPv4> map = getMap();
                File file = new File("./data/subnet4.map");
                FileOutputStream outputStream = new FileOutputStream(file);
                try {
                    SerializationUtils.serialize(map, outputStream);
                    // Atualiza flag de atualização.
                    CHANGED = false;
                } finally {
                    outputStream.close();
                }
                Server.logStore(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static synchronized SubnetIPv4 put(Long key, SubnetIPv4 subnet) {
        return MAP.put(key, subnet);
    }
    
    /**
     * Carregamento de cache do disco.
     */
    public static void load() {
        long time = System.currentTimeMillis();
        File file = new File("./data/subnet4.map");
        if (file.exists()) {
            try {
                TreeMap<Object,Object> map;
                FileInputStream fileInputStream = new FileInputStream(file);
                try {
                    map = SerializationUtils.deserialize(fileInputStream);
                } finally {
                    fileInputStream.close();
                }
                for (Object value : map.values()) {
                    if (value instanceof SubnetIPv4) {
                        SubnetIPv4 sub4 = (SubnetIPv4) value;
                        sub4.normalize();
                        String cidr = sub4.getInetnum();
                        String ip = getFirstIPv4(cidr);
                        Long key = getLongIP(ip);
                        put(key, sub4);
                    }
                }
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
    
    public static boolean containsIPv4(String cidr, String ip) {
        if (isValidCIDRv4(cidr) && isValidIPv4(ip)) {
            cidr = Subnet.normalizeCIDR(cidr);
            int mask = SubnetIPv4.getMaskNet(cidr);
            int address1 = SubnetIPv4.getAddressNet(cidr);
            int address2 = SubnetIPv4.getAddressIP(ip);
            return (address1 & mask) == (address2 & mask);
        } else {
            return false;
        }
    }
    
    public int compareTo(SubnetIPv4 other) {
        return new Integer(this.address).compareTo(other.address);
    }
    
    /**
     * Mapa completo dos blocos alocados aos países.
     */
    private static final TreeMap<Long,SubnetIPv4> SERVER_MAP = new TreeMap<Long,SubnetIPv4>();
    
    /**
     * Adiciona um servidor WHOIS na lista com seu respecitivo bloco.
     * @param inetnum o endereço de bloco em notação CIDR.
     * @param server o servidor WHOIS responsável por aquele bloco.
     */
    private static void addServer(String inetnum, String server) {
        try {
            SubnetIPv4 subnet = new SubnetIPv4(inetnum, server);
            String ip = getFirstIPv4(subnet.getInetnum());
            Long key = getLongIP(ip);
            SERVER_MAP.put(key, subnet);
        } catch (Exception ex) {
            Server.logError(ex);
        }
    }
    
    // Temporário
    @Override
    public String getWhoisServer() throws ProcessException {
        String ip = getFirstIPv4(getInetnum());
        return getWhoisServer(ip);
    }
    
    /**
     * Retorna o servidor que possui a informação de bloco IPv4 de AS de um IP.
     * @param address endereço IP em inteiro de 32 bits.
     * @return o servidor que possui a informação de bloco IPv4 de AS de um IP.
     * @throws QueryException se o bloco não for encontrado para o IP especificado.
     */
    private static String getWhoisServer(String ip) throws ProcessException {
        // Busca eficiente O(log2(n)).
        // Este método só funciona se o mapa não tiver intersecção de blocos.
        Long key = getLongIP(ip);
        key = SERVER_MAP.floorKey(key);
        if (key == null) {
            throw new ProcessException("ERROR: SERVER NOT FOUND");
        } else {
            SubnetIPv4 subnet = SERVER_MAP.get(key);
            if (subnet.contains(ip)) {
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
