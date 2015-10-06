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
import java.util.Arrays;
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Pattern;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Representa uma Subnet de IPv6.
 * 
 * <h2>Mecanismo de busca</h2>
 * A busca de um bloco AS é realizada através de um mapa ordenado em árvore,
 * onde a chave é o primeiro endereço IP do bloco, 
 * convetido em inteiro de 64 bits, e o valor é o bloco propriamente dito.
 * O endereço IP da consulta é convertido em inteiro de 64 bits e localiza-se 
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
public final class SubnetIPv6 extends Subnet
//implements Comparable<SubnetIPv6>
{
    
    private static final long serialVersionUID = 1L;
    
    private final long address; // Primeiro endereço do bloco, primeiros 64 bits.
    private final long mask; // Máscara da subrede, primeiros 64 bits.
    
    /**
     * Construtor do blocos de países.
     * @param inetnum o endereçamento CIDR do bloco.
     * @param server o server que possui as informações daquele bloco.
     */
    protected SubnetIPv6(String inetnum, String server) {
        super(inetnum, server);
        // Endereçamento do bloco.
        this.mask = getMaskNet(inetnum);
        this.address = getAddressNet(inetnum) & mask; // utiliza a máscara para garantir que o endereço passado seja o primeiro endereço do bloco.
    }
    
    /**
     * Retorna o primeiro endereço do bloco em inteiro de 64 bits.
     * @return o primeiro endereço do bloco em inteiro de 64 bits.
     */
    public long getFirstAddress() {
        return address;
    }
    
    /**
     * Retorna o último endereço do bloco em inteiro de 64 bits.
     * @return o último endereço do bloco em inteiro de 64 bits.
     */
    public long getLastAddress() {
        return address | ~mask;
    }
    
    /**
     * Construtor do blocos de alocados para ASs.
     * @param result o resultado WHOIS do bloco.
     * @throws QueryException se houver alguma falha da atualização do registro.
     */
    private SubnetIPv6(String result) throws ProcessException {
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
     * Retorna o endereço IP em inteiro de 64 bits da notação CIDR.
     * @param inetnum endereço de bloco em notação CIDR.
     * @return o endereço IP em inteiro de 64 bits da notação CIDR.
     */
    private static long getAddressNet(String inetnum) {
        int index = inetnum.indexOf('/');
        String ip = inetnum.substring(0, index);
        return getAddressIP(ip);
    }
    
    /**
     * Divide o endereço IPv6 em 16 bytes,
     * cada um na ordem correta dos blocos.
     * @param ip o endereço IPv6.
     * @return um vetor de 16 bytes representando o endereço IPv6.
     */
    public static byte[] splitByte(String ip) {
        byte[] address = new byte[16];
        int k = 0;
        for (short block : split(ip)) {
            address[k++] |= block >>> 8;
            address[k++] |= block;
        }
        return address;
    }
    
    public static short[] split(String ip, short[] mask) {
        short[] address = split(ip);
        for (int i = 0; i < 8; i++) {
            address[i] &= mask[i];
        }
        return address;
    }
    
    /**
     * Retorna a mácara IPv6 em 8 partes.
     * @param size o tamanho em bits da máscara que deve ser criada.
     * @return a mácara IPv6 em 8 partes.
     */
    public static short[] getMaskIPv6(String size) {
        return getMaskIPv6(Integer.parseInt(size));
    }
    
    /**
     * Retorna a mácara IPv6 em 8 partes.
     * @param size o tamanho em bits da máscara que deve ser criada.
     * @return a mácara IPv6 em 8 partes.
     */
    public static short[] getMaskIPv6(int size) {
        short[] mask = new short[8];
        int n = size / 16;
        int r = size % 16;
        int i;
        for (i = 0; i < n; i++) {
            mask[i] = (short) 0xFFFF;
        }
        if (i < n) {
            mask[i] = (short) (0xFFFF << 16 - r);
        }
        return mask;
    }
    
    public static String reverse(String ip) {
        String reverse = "";
        byte[] address = splitByte(ip);
        for (byte octeto : address) {
            String hexPart = Integer.toHexString((int) octeto & 0xFF);
            if (hexPart.length() == 1) {
                hexPart = "0" + hexPart;
            }
            for (char digit : hexPart.toCharArray()) {
                reverse = digit + "." + reverse;
            }
        }
        return reverse;
    }
    
    /**
     * Meio mais seguro de padronizar os endereços IP.
     * @param ip o endereço IPv6.
     * @return o endereço IPv6 padronizado.
     */
    public static String normalizeIPv6(String ip) {
        short[] splitedIP = split(ip);
        int p1 = splitedIP[0] & 0xFFFF;
        int p2 = splitedIP[1] & 0xFFFF;
        int p3 = splitedIP[2] & 0xFFFF;
        int p4 = splitedIP[3] & 0xFFFF;
        int p5 = splitedIP[4] & 0xFFFF;
        int p6 = splitedIP[5] & 0xFFFF;
        int p7 = splitedIP[6] & 0xFFFF;
        int p8 = splitedIP[7] & 0xFFFF;
        return Integer.toHexString(p1) + ":" +
                Integer.toHexString(p2) + ":" +
                Integer.toHexString(p3) + ":" +
                Integer.toHexString(p4) + ":" +
                Integer.toHexString(p5) + ":" +
                Integer.toHexString(p6) + ":" +
                Integer.toHexString(p7) + ":" +
                Integer.toHexString(p8);
    }
    
    /**
     * Divide o endereço IPv6 em 8 inteiros,
     * cada um na ordem correta dos blocos.
     * @param ip o endereço IPv6.
     * @return um vetor de 8 inteiros representando o endereço IPv6.
     */
    public static short[] split(String ip) {
        int k = 0;
        short[] address = new short[8];
        int beginIndex = 0;
        int endIndex;
        int count = 0;
        // Converte do inicio ao final.
        while ((endIndex = ip.indexOf(':', beginIndex)) != -1) {
            if (beginIndex == endIndex) {
                // Encontrou a abreviação central.
                break;
            } else {
                String block = ip.substring(beginIndex, endIndex);
                address[k++] |= Integer.valueOf(block, 16);
                beginIndex = endIndex + 1;
                count++;
            }
        }
        k = 7;
        count = 8 - count; // Calcula quantos blocos faltaram.
        endIndex = ip.length();
        // Converte invertido do final ao inicio.
        while (count-- > 0 && (beginIndex = ip.lastIndexOf(':', endIndex)) != -1) {
            if (beginIndex == endIndex) {
                // Encontrou a abreviação central.
                break;
            } else if (beginIndex+1 == endIndex) {
                // Final abreviado.
                break;
            } else {
                String block = ip.substring(beginIndex+1, endIndex);
                address[k--] |= Integer.valueOf(block, 16);
                endIndex = beginIndex - 1;
            }
        }
        return address;
    }
    
    /**
     * Retorna o endereço IP em inteiro de 64 bits da notação IP.
     * Para fins de roteamento, os primeiros 64 são suficientes.
     * @param ip endereço de IP em notação IP.
     * @return o endereço IP em inteiro de 64 bits da notação IPv6.
     */
    protected static long getAddressIP(String ip) {
        long address = 0;
        short[] splitedAddress = split(ip);
        for (int i = 0; i < 4; i++) {
            address += (long) splitedAddress[i] & 0xFFFF;
            if (i < 3) {
                address <<= 16;
            }
        }
        return address;
    }
    
    /**
     * Retorna a máscara em inteiro de 64 bits da notação CIDR.
     * @param inetnum endereço de bloco em notação CIDR.
     * @return a máscara em inteiro de 64 bits da notação CIDR.
     */
    private static long getMaskNet(String inetnum) {
        int index = inetnum.indexOf('/');
        int mask = Integer.parseInt(inetnum.substring(index+1));
        return 0xFFFFFFFFFFFFFFFFL << 64 - mask;
    }
    
    /**
     * Verifica se um IP é válido na notação de IP.
     * @param ip o IP a ser verificado.
     * @return verdadeiro se um IP é válido na notação de IPv6.
     */
    public static boolean isValidIPv6(String ip) {
        ip = ip.trim();
        ip = ip.toLowerCase();
        return Pattern.matches("^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
                + "([0-9a-fA-F]{1,4}:){1,7}:|"
                + "([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
                + "([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
                + "([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
                + "([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
                + "([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
                + "[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
                + ":((:[0-9a-fA-F]{1,4}){1,7}|:)|"
                + "fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|"
                + "::(ffff(:0{1,4}){0,1}:){0,1}"
                + "((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}"
                + "(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|"
                + "([0-9a-fA-F]{1,4}:){1,4}:"
                + "((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}"
                + "(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$", ip);
//        return Pattern.matches("^"
//                + "([\\da-f]{1,4}:|((?=.*(::))(?!.*\\3.+\\3))\\3?)"
//                + "([\\da-f]{1,4}(\\3|:\\b)|\\2){5}"
//                + "(([\\da-f]{1,4}(\\3|:\\b|$)|\\2){2}|(((2[0-4]|1\\d|[1-9])?\\d|25[0-5])\\.?\\b){4})"
//                + "/[0-9]{1,3}"
//                + "$", ip);
    }
    
    /**
     * Verifica se um CIDR é válido na notação de IPv6.
     * @param cidr o CIDR a ser verificado.
     * @return verdadeiro se um CIDR é válido na notação de IPv6.
     */
    public static boolean isValidCIDRv6(String cidr) {
        cidr = cidr.trim();
        cidr = cidr.toLowerCase();
//        return Pattern.matches("^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
//                + "([0-9a-fA-F]{1,4}:){1,7}:|"
//                + "([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
//                + "([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
//                + "([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
//                + "([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
//                + "([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
//                + "[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
//                + ":((:[0-9a-fA-F]{1,4}){1,7}|:)|"
//                + "fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|"
//                + "::(ffff(:0{1,4}){0,1}:){0,1}"
//                + "((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}"
//                + "(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|"
//                + "([0-9a-fA-F]{1,4}:){1,4}:"
//                + "((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}"
//                + "(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])/[0-9]{1,3}$", cidr);
        return Pattern.matches("^"
                + "([\\da-f]{1,4}:|((?=.*(::))(?!.*\\3.+\\3))\\3?)"
                + "([\\da-f]{1,4}(\\3|:\\b)|\\2){5}"
                + "(([\\da-f]{1,4}(\\3|:\\b|$)|\\2){2}|(((2[0-4]|1\\d|[1-9])?\\d|25[0-5])\\.?\\b){4})"
                + "/[0-9]{1,3}"
                + "$", cidr);
    }
    
    /**
     * Mapa de blocos IP de ASs com busca em árvore binária log2(n).
     */
    private static final TreeMap<Long,SubnetIPv6> SUBNET_MAP = new TreeMap<Long,SubnetIPv6>();
    
    /**
     * Adciiona o registro de bloco de IP no cache.
     * @param subnet o de bloco de IP que deve ser adicionado.
     */
    private static synchronized void addSubnet(SubnetIPv6 subnet) {
        SUBNET_MAP.put(subnet.address, subnet);
        // Atualiza flag de atualização.
        SUBNET_CHANGED = true;
    }
    
    /**
     * Remove o registro de bloco de IP do cache.
     * @param subnet o de bloco de IP que deve ser removido.
     */
    private static synchronized void removeSubnet(SubnetIPv6 subnet) {
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
    public static synchronized SubnetIPv6 removeSubnet(String ip) {
        long address = getAddressIP(ip.trim()); // Implementar validação.
        // Busca eficiente O(log2(n)).
        // Este método só funciona se o mapa não tiver intersecção de blocos.
        Long key = SUBNET_MAP.floorKey(address);
        if (key == null && !SUBNET_MAP.isEmpty()) {
            // Devido à limitação do Java em não traballhar com unsigned int,
            // fazer uma consulta circular pelo último bloco do mapa.
            key = SUBNET_MAP.lastKey();
        }
        if (key == null) {
            return null;
        } else {
            SubnetIPv6 subnet = SUBNET_MAP.remove(key);
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
        long address = getAddressIP(ip.trim()); // Implementar validação.
        // Busca eficiente O(log2(n)).
        // Este método só funciona se o mapa não tiver intersecção de blocos.
        Long key = SUBNET_MAP.floorKey(address);
        if (key == null && !SUBNET_MAP.isEmpty()) {
            // Devido à limitação do Java em não traballhar com unsigned int,
            // fazer uma consulta circular pelo último bloco do mapa.
            key = SUBNET_MAP.lastKey();
        }
        if (key != null) {
            // Encontrou uma subrede com endereço inicial imediatemente inferior.
            SubnetIPv6 subnet = SUBNET_MAP.get(key);
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
        SubnetIPv6 subnet = new SubnetIPv6(result);
        subnet.server = server; // Temporário até final de transição.
        addSubnet(subnet);
    }
    
    /**
     * Corrige o endereço da notação CIDR para sem abreviação.
     * @param inetnum o endereço com notação CIDR sem abreviação.
     * @return o endereço da notação CIDR sem abreviação.
     */
    protected static String normalizeCIDRv6(String inetnum) {
        int index = inetnum.indexOf('/');
        String ip = inetnum.substring(0, index);
        String size = inetnum.substring(index+1);
        int sizeInt = Integer.parseInt(size);
        short[] mask = SubnetIPv6.getMaskIPv6(sizeInt);
        short[] address = SubnetIPv6.split(ip, mask);
        int p1 = address[0] & 0xFFFF;
        int p2 = address[1] & 0xFFFF;
        int p3 = address[2] & 0xFFFF;
        int p4 = address[3] & 0xFFFF;
        int p5 = address[4] & 0xFFFF;
        int p6 = address[5] & 0xFFFF;
        int p7 = address[6] & 0xFFFF;
        int p8 = address[7] & 0xFFFF;
        return Integer.toHexString(p1) + ":" +
                Integer.toHexString(p2) + ":" +
                Integer.toHexString(p3) + ":" +
                Integer.toHexString(p4) + ":" +
                Integer.toHexString(p5) + ":" +
                Integer.toHexString(p6) + ":" +
                Integer.toHexString(p7) + ":" +
                Integer.toHexString(p8) + "/" + sizeInt;
    }
    
    public static String getInetnum(String ip) {
        try {
            SubnetIPv6 subnet = getSubnet(ip);
            return normalizeCIDRv6(subnet.get("inetnum", false));
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
    
    public static String getOwnerID(String ip) {
        try {
            SubnetIPv6 subnet = getSubnet(ip);
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
    
    public static String getOwnerC(String ip) {
        try {
            SubnetIPv6 subnet = getSubnet(ip);
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
    
    /**
     * Retorna o bloco de IP de AS de um determinado IP.
     * @param ip o IP cujo bloco deve ser retornado.
     * @return o registro de bloco IPv6 de AS de um determinado IP.
     * @throws ProcessException se houver falha no processamento.
     */
    public static SubnetIPv6 getSubnet(String ip) throws ProcessException {
        long address = getAddressIP(ip.trim()); // Implementar validação.
        // Busca eficiente O(log2(n)).
        // Este método só funciona se o mapa não tiver intersecção de blocos.
        Long key = SUBNET_MAP.floorKey(address);
        if (key == null && !SUBNET_MAP.isEmpty()) {
            // Devido à limitação do Java em não traballhar com unsigned int,
            // fazer uma consulta circular pelo último bloco do mapa.
            key = SUBNET_MAP.lastKey();
        }
        if (key != null) {
            // Encontrou uma subrede com endereço inicial imediatemente inferior.
            SubnetIPv6 subnet = SUBNET_MAP.get(key);
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
        SubnetIPv6 subnet = new SubnetIPv6(result);
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
                File file = new File("./data/subnet6.map");
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
        File file = new File("./data/subnet6.map");
        if (file.exists()) {
            try {
                TreeMap<Long,SubnetIPv6> map;
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
    
    public static boolean containsIPv6(String cidr, String ip) {
        if (isValidCIDRv6(cidr) && isValidIPv6(ip)) {
            int index = cidr.lastIndexOf('/');
            String size = cidr.substring(index + 1);
            String address = cidr.substring(0, index);
            short[] mask = SubnetIPv6.getMaskIPv6(size);
            short[] address1 = SubnetIPv6.split(address, mask);
            short[] address2 = SubnetIPv6.split(ip, mask);
            return Arrays.equals(address1, address2);
        } else {
            return false;
        }
    }
    
    /**
     * Verifica se o endereço IP passado faz parte do bloco.
     * @param ip o endereço IP em notação IPv6.
     * @return verdadeiro se o endereço IP passado faz parte do bloco.
     */
    public boolean contains(String ip) {
        return contains(getAddressIP(ip));
    }
    
    /**
     * Verifica se o endereço IP passado faz parte do bloco.
     * @param ip o endereço IP em inteiro de 64 bits.
     * @return verdadeiro se o endereço IP passado faz parte do bloco.
     */
    public boolean contains(long ip) {
        return this.address == (ip & mask);
    }
    
//    @Override
    public int compareTo(SubnetIPv6 other) {
        return new Long(this.address).compareTo(other.address);
    }
    
    /**
     * Mapa completo dos blocos alocados aos países.
     */
    private static final TreeMap<Long,SubnetIPv6> SERVER_MAP = new TreeMap<Long,SubnetIPv6>();
    
    /**
     * Adiciona um servidor WHOIS na lista com seu respecitivo bloco.
     * @param inetnum o endereço de bloco em notação CIDR.
     * @param server o servidor WHOIS responsável por aquele bloco.
     */
    private static void addServer(String inetnum, String server) {
        try {
            SubnetIPv6 subnet = new SubnetIPv6(inetnum, server);
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
     * Retorna o servidor que possui a informação de bloco IPv6 de AS de um IP.
     * @param address endereço IP em inteiro de 64 bits.
     * @return o servidor que possui a informação de bloco IPv6 de AS de um IP.
     * @throws QueryException se o bloco não for encontrado para o IP especificado.
     */
    private static String getWhoisServer(long address) throws ProcessException {
        // Busca eficiente O(log2(n)).
        // Este método só funciona se o mapa não tiver intersecção de blocos.
        Long key = SERVER_MAP.floorKey(address);
        if (key == null && !SERVER_MAP.isEmpty()) {
            key = SERVER_MAP.lastKey();
        }
        if (key == null) {
            throw new ProcessException("ERROR: SERVER NOT FOUND");
        } else {
            SubnetIPv6 subnet = SERVER_MAP.get(key);
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
        addServer("2001:1280::/25", Server.WHOIS_BR);
        addServer("2801:80::/26", Server.WHOIS_BR);
        addServer("2804::/16", Server.WHOIS_BR);
    }
}
