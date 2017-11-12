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
import java.math.BigInteger;
import java.util.Arrays;
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
public final class SubnetIPv6 extends Subnet {
    
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
        CHANGED = true;
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
        if (i < mask.length && r > 0) {
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
    
    public static boolean isSLAAC(String ip) {
        if (SubnetIPv6.isValidIPv6(ip)) {
            byte[] byteArray = splitByte(ip);
            return (byteArray[11] & 0xFF) == 0xFF && (byteArray[12] & 0xFF) == 0xFE;
        } else {
            return false;
        }
    }
    
    public static boolean is6to4(String ip) {
        if (SubnetIPv6.isValidIPv6(ip)) {
            short[] shortArray = SubnetIPv6.split(ip);
            return shortArray[0] == 0x2002;
        } else {
            return false;
        }
    }
    
    public static boolean isTeredo(String ip) {
        if (SubnetIPv6.isValidIPv6(ip)) {
            short[] shortArray = SubnetIPv6.split(ip);
            return shortArray[0] == 0x2001 && shortArray[1] == 0x0000;
        } else {
            return false;
        }
    }
    
    public static String getIPv4(String ip) {
        if (ip == null) {
            return null;
        } else if (is6to4(ip)) {
            byte[] byteArray = splitByte(ip);
            int octet1 = byteArray[2] & 0xFF;
            int octet2 = byteArray[3] & 0xFF;
            int octet3 = byteArray[4] & 0xFF;
            int octet4 = byteArray[5] & 0xFF;
            return octet1 + "." + octet2 + "." + octet3 + "." + octet4;
        } else if (isTeredo(ip)) {
            byte[] byteArray = splitByte(ip);
            int octet1 = ~byteArray[12] & 0xFF;
            int octet2 = ~byteArray[13] & 0xFF;
            int octet3 = ~byteArray[14] & 0xFF;
            int octet4 = ~byteArray[15] & 0xFF;
            return octet1 + "." + octet2 + "." + octet3 + "." + octet4;
        } else {
            return null;
        }
    }
    
    public static String tryTransformToIPv4(String ip) {
        if (ip == null) {
            return null;
        } else if (is6to4(ip)) {
            byte[] byteArray = splitByte(ip);
            int octet1 = byteArray[2] & 0xFF;
            int octet2 = byteArray[3] & 0xFF;
            int octet3 = byteArray[4] & 0xFF;
            int octet4 = byteArray[5] & 0xFF;
            return octet1 + "." + octet2 + "." + octet3 + "." + octet4;
        } else if (isTeredo(ip)) {
            byte[] byteArray = splitByte(ip);
            int octet1 = ~byteArray[12] & 0xFF;
            int octet2 = ~byteArray[13] & 0xFF;
            int octet3 = ~byteArray[14] & 0xFF;
            int octet4 = ~byteArray[15] & 0xFF;
            return octet1 + "." + octet2 + "." + octet3 + "." + octet4;
        } else {
            return ip;
        }
    }
    
    public static String expandIPv6(String ip) {
        short[] splitedIP = split(ip);
        int p1 = splitedIP[0] & 0xFFFF;
        int p2 = splitedIP[1] & 0xFFFF;
        int p3 = splitedIP[2] & 0xFFFF;
        int p4 = splitedIP[3] & 0xFFFF;
        int p5 = splitedIP[4] & 0xFFFF;
        int p6 = splitedIP[5] & 0xFFFF;
        int p7 = splitedIP[6] & 0xFFFF;
        int p8 = splitedIP[7] & 0xFFFF;
        return String.format("%4s", Integer.toHexString(p1)).replace(' ', '0') + ":" +
                String.format("%4s", Integer.toHexString(p2)).replace(' ', '0') + ":" +
                String.format("%4s", Integer.toHexString(p3)).replace(' ', '0') + ":" +
                String.format("%4s", Integer.toHexString(p4)).replace(' ', '0') + ":" +
                String.format("%4s", Integer.toHexString(p5)).replace(' ', '0') + ":" +
                String.format("%4s", Integer.toHexString(p6)).replace(' ', '0') + ":" +
                String.format("%4s", Integer.toHexString(p7)).replace(' ', '0') + ":" +
                String.format("%4s", Integer.toHexString(p8)).replace(' ', '0');
    }
    
    public static String expandCIDRv6(String cidr) {
        int index = cidr.indexOf('/');
        String ip = cidr.substring(0, index);
        String mask = cidr.substring(index);
        ip = expandIPv6(ip);
        cidr = ip + mask;
        return cidr;
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
        endIndex = ip.length()-1;
        // Converte invertido do final ao inicio.
        while (count-- > 0 && (beginIndex = ip.lastIndexOf(':', endIndex)) != -1) {
            if (beginIndex == endIndex) {
                // Encontrou a abreviação central.
                break;
            } else {
                String block = ip.substring(beginIndex+1, endIndex+1);
                address[k--] |= Integer.valueOf(block, 16);
                endIndex = beginIndex - 1;
            }
        }
        return address;
    }
    
    public static byte[] address(String ip) {
        byte[] address = new byte[16];
        short[] splitArray = split(ip);
        address[0] = (byte) (splitArray[0] >>> 8 & 0xFFFF);
        address[1] = (byte) (splitArray[0] & 0xFFFF);
        address[2] = (byte) (splitArray[1] >>> 8 & 0xFFFF);
        address[3] = (byte) (splitArray[1] & 0xFFFF);
        address[4] = (byte) (splitArray[2] >>> 8 & 0xFFFF);
        address[5] = (byte) (splitArray[2] & 0xFFFF);
        address[6] = (byte) (splitArray[3] >>> 8 & 0xFFFF);
        address[7] = (byte) (splitArray[3] & 0xFFFF);
        address[8] = (byte) (splitArray[4] >>> 8 & 0xFFFF);
        address[9] = (byte) (splitArray[4] & 0xFFFF);
        address[10] = (byte) (splitArray[5] >>> 8 & 0xFFFF);
        address[11] = (byte) (splitArray[5] & 0xFFFF);
        address[12] = (byte) (splitArray[6] >>> 8 & 0xFFFF);
        address[13] = (byte) (splitArray[6] & 0xFFFF);
        address[14] = (byte) (splitArray[7] >>> 8 & 0xFFFF);
        address[15] = (byte) (splitArray[7] & 0xFFFF);
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
        if (ip == null) {
            return false;
        } else {
            ip = ip.trim();
            ip = ip.toLowerCase();
            return Pattern.matches("^"
                    + "([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
                    + "([0-9a-fA-F]{1,4}:){1,7}:|"
                    + "([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
                    + "([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
                    + "([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
                    + "([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
                    + "([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
                    + "[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
                    + ":((:[0-9a-fA-F]{1,4}){1,7}|:)|"
                    + "fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}"
                    + "$", ip
                    );
        }
    }
    
    public static boolean isReservedIPv6(String ip) {
        if (ip == null) {
            return false;
        } else if (SubnetIPv6.containsIP("0000::/8", ip)) {
            return true;
        } else if (SubnetIPv6.containsIP("0100::/8", ip)) {
            return true;
        } else if (SubnetIPv6.containsIP("0200::/7", ip)) {
            return true;
        } else if (SubnetIPv6.containsIP("0400::/6", ip)) {
            return true;
        } else if (SubnetIPv6.containsIP("0800::/5", ip)) {
            return true;
        } else if (SubnetIPv6.containsIP("1000::/4", ip)) {
            return true;
        } else if (SubnetIPv6.containsIP("2001::/32", ip)) {
            return true;
        } else if (SubnetIPv6.containsIP("2001:10::/28", ip)) {
            return true;
        } else if (SubnetIPv6.containsIP("2001:20::/28", ip)) {
            return true;
        } else if (SubnetIPv6.containsIP("2001:db8::/32", ip)) {
            return true;
        } else if (SubnetIPv6.containsIP("2002::/16", ip)) {
            return true;
        } else if (SubnetIPv6.containsIP("4000::/3", ip)) {
            return true;
        } else if (SubnetIPv6.containsIP("6000::/3", ip)) {
            return true;
        } else if (SubnetIPv6.containsIP("8000::/3", ip)) {
            return true;
        } else if (SubnetIPv6.containsIP("a000::/3", ip)) {
            return true;
        } else if (SubnetIPv6.containsIP("c000::/3", ip)) {
            return true;
        } else if (SubnetIPv6.containsIP("e000::/4", ip)) {
            return true;
        } else if (SubnetIPv6.containsIP("f000::/5", ip)) {
            return true;
        } else if (SubnetIPv6.containsIP("f800::/6", ip)) {
            return true;
        } else if (SubnetIPv6.containsIP("fc00::/7", ip)) {
            return true;
        } else if (SubnetIPv6.containsIP("fe00::/9", ip)) {
            return true;
        } else if (SubnetIPv6.containsIP("fe80::/10", ip)) {
            return true;
        } else if (SubnetIPv6.containsIP("fec0::/10", ip)) {
            return true;
        } else if (SubnetIPv6.containsIP("ff00::/8", ip)) {
            return true;
        } else {
            return false;
        }
    }
    
    private static BigInteger ADDRESS_MIN = new BigInteger("0");
    private static BigInteger ADDRESS_MAX = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
    private static BigInteger ADDRESS_UNIT = new BigInteger("1");
    private static BigInteger ADDRESS_OCTET = new BigInteger("FFFF", 16);
    
    public static String getNextIPv6(String ip) {
        if (ip == null) {
            return null;
        } else if (SubnetIPv6.isValidIPv6(ip)) {
            BigInteger address = new BigInteger(1, address(ip));
            if (address.equals(ADDRESS_MAX)) {
                return null;
            } else {
                address = address.add(ADDRESS_UNIT);
                int p8 = address.and(ADDRESS_OCTET).intValue();
                address = address.shiftRight(16);
                int p7 = address.and(ADDRESS_OCTET).intValue();
                address = address.shiftRight(16);
                int p6 = address.and(ADDRESS_OCTET).intValue();
                address = address.shiftRight(16);
                int p5 = address.and(ADDRESS_OCTET).intValue();
                address = address.shiftRight(16);
                int p4 = address.and(ADDRESS_OCTET).intValue();
                address = address.shiftRight(16);
                int p3 = address.and(ADDRESS_OCTET).intValue();
                address = address.shiftRight(16);
                int p2 = address.and(ADDRESS_OCTET).intValue();
                address = address.shiftRight(16);
                int p1 = address.and(ADDRESS_OCTET).intValue();
                return Integer.toHexString(p1) + ":" +
                        Integer.toHexString(p2) + ":" +
                        Integer.toHexString(p3) + ":" +
                        Integer.toHexString(p4) + ":" +
                        Integer.toHexString(p5) + ":" +
                        Integer.toHexString(p6) + ":" +
                        Integer.toHexString(p7) + ":" +
                        Integer.toHexString(p8);
            }
        } else {
            return null;
        }
    }
    public static String getPreviousIPv6(String ip) {
        if (ip == null) {
            return null;
        } else if (SubnetIPv6.isValidIPv6(ip)) {
            BigInteger address = new BigInteger(1, address(ip));
            if (address.equals(ADDRESS_MIN)) {
                return null;
            } else {
                address = address.subtract(ADDRESS_UNIT);
                int p8 = address.and(ADDRESS_OCTET).intValue();
                address = address.shiftRight(16);
                int p7 = address.and(ADDRESS_OCTET).intValue();
                address = address.shiftRight(16);
                int p6 = address.and(ADDRESS_OCTET).intValue();
                address = address.shiftRight(16);
                int p5 = address.and(ADDRESS_OCTET).intValue();
                address = address.shiftRight(16);
                int p4 = address.and(ADDRESS_OCTET).intValue();
                address = address.shiftRight(16);
                int p3 = address.and(ADDRESS_OCTET).intValue();
                address = address.shiftRight(16);
                int p2 = address.and(ADDRESS_OCTET).intValue();
                address = address.shiftRight(16);
                int p1 = address.and(ADDRESS_OCTET).intValue();
                return Integer.toHexString(p1) + ":" +
                        Integer.toHexString(p2) + ":" +
                        Integer.toHexString(p3) + ":" +
                        Integer.toHexString(p4) + ":" +
                        Integer.toHexString(p5) + ":" +
                        Integer.toHexString(p6) + ":" +
                        Integer.toHexString(p7) + ":" +
                        Integer.toHexString(p8);
            }
        } else {
            return null;
        }
    }
    
    /**
     * Verifica se um CIDR é válido na notação de IPv6.
     * @param cidr o CIDR a ser verificado.
     * @return verdadeiro se um CIDR é válido na notação de IPv6.
     */
    public static boolean isValidCIDRv6(String cidr) {
        if (cidr == null) {
            return false;
        } else {
            cidr = cidr.trim();
            cidr = cidr.toLowerCase();
            return Pattern.matches("^"
                    + "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
                    + "([0-9a-fA-F]{1,4}:){1,7}:|"
                    + "([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
                    + "([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
                    + "([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
                    + "([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
                    + "([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
                    + "[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
                    + ":((:[0-9a-fA-F]{1,4}){1,7}|:)|"
                    + "fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,})"
                    + "/[0-9]{1,3}$", cidr
                    );
        }
    }
    
    public static boolean isReverseIPv6(String reverse) {
        reverse = reverse.trim();
        reverse = reverse.toLowerCase();
        return Pattern.matches("^"
                + "(\\.?[a-f0-9]{1,4})"
                + "(\\.[a-f0-9]{1,4}){31}"
                + "$\\.?", reverse);
    }
    
    public static String reverseToIPv6(String reverse) {
        reverse = reverse.replace(".", "");
        char[] charArray = reverse.toCharArray();
        StringBuilder builder = new StringBuilder();
        for (int index = charArray.length-1; index>=0; index--) {
            char digit = charArray[index];
            builder.append(digit);
            if (index % 4 == 0) {
                builder.append(':');
            }
        }
        String ip = builder.toString();
        return SubnetIPv6.normalizeIPv6(ip);
    }
    
    /**
     * Mapa de blocos IP de ASs com busca em árvore binária log2(n).
     */
    private static final TreeMap<String,SubnetIPv6> MAP = new TreeMap<String,SubnetIPv6>();
    
    @Override
    public synchronized SubnetIPv6 drop() {
        String cidr = getInetnum();
        String first = SubnetIPv6.getFirstIP(cidr);
        String key = expandIPv6(first);
        return MAP.remove(key);
    }
    
    /**
     * Remove registro de bloco de IP para AS do cache.
     * @param ip o IP cujo bloco deve ser removido.
     * @return o registro de bloco removido, se existir.
     */
    public static synchronized SubnetIPv6 removeSubnet(String ip) {
        // Busca eficiente O(log2(n)).
        // Este método só funciona se o mapa não tiver intersecção de blocos.
        String key = expandIPv6(ip);
        key = MAP.floorKey(key);
        if (key == null) {
            return null;
        } else {
            SubnetIPv6 subnet = MAP.remove(key);
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
        SubnetIPv6 subnet;
        String key = MAP.floorKey(expandIPv6(ip));
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
        subnet = new SubnetIPv6(result);
        subnet.server = server; // Temporário até final de transição.
        key = getFirstIPv6(subnet.getInetnum());
        key = expandIPv6(key);
        MAP.put(key, subnet);
        CHANGED = true;
    }
    
    public static String getFirstIPv6(String inetnum) {
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
                Integer.toHexString(p8);
    }
    
    public static String getLastIPv6(String inetnum) {
        int index = inetnum.indexOf('/');
        String ip = inetnum.substring(0, index);
        String size = inetnum.substring(index+1);
        int sizeInt = Integer.parseInt(size);
        short[] mask = SubnetIPv6.getMaskIPv6(sizeInt);
        short[] address = SubnetIPv6.split(ip, mask);
        int p1 = (address[0] & 0xFFFF) ^ (~mask[0] & 0xFFFF);
        int p2 = (address[1] & 0xFFFF) ^ (~mask[1] & 0xFFFF);
        int p3 = (address[2] & 0xFFFF) ^ (~mask[2] & 0xFFFF);
        int p4 = (address[3] & 0xFFFF) ^ (~mask[3] & 0xFFFF);
        int p5 = (address[4] & 0xFFFF) ^ (~mask[4] & 0xFFFF);
        int p6 = (address[5] & 0xFFFF) ^ (~mask[5] & 0xFFFF);
        int p7 = (address[6] & 0xFFFF) ^ (~mask[6] & 0xFFFF);
        int p8 = (address[7] & 0xFFFF) ^ (~mask[7] & 0xFFFF);
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
     * Corrige o endereço da notação CIDR para sem abreviação.
     * @param inetnum o endereço com notação CIDR sem abreviação.
     * @return o endereço da notação CIDR sem abreviação.
     */
    public static String normalizeCIDRv6(String inetnum) {
        if (inetnum == null) {
            return null;
        } else {
            int index = inetnum.indexOf('/');
            String ip = inetnum.substring(0, index);
            String size = inetnum.substring(index+1);
            int sizeInt = Integer.parseInt(size);
            if (sizeInt < 0 || sizeInt > 128) {
                return null;
            } else {
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
        }
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
    
    private static synchronized SubnetIPv6 newSubnet(String ip) throws ProcessException {
//        Server.logTrace("quering new WHOIS IPv6");
        // Selecionando servidor da pesquisa WHOIS.
        String server = getWhoisServer(ip);
        // Fazer a consulta no WHOIS.
        String result = Server.whois(ip, server);
        SubnetIPv6 subnet = new SubnetIPv6(result);
        subnet.server = server; // Temporário até final de transição.
        String key = getFirstIPv6(subnet.getInetnum());
        key = expandIPv6(key);
        MAP.put(key, subnet);
        CHANGED = true;
        return subnet;
    }
    
    /**
     * Retorna o bloco de IP de AS de um determinado IP.
     * @param ip o IP cujo bloco deve ser retornado.
     * @return o registro de bloco IPv6 de AS de um determinado IP.
     * @throws ProcessException se houver falha no processamento.
     */
    public static SubnetIPv6 getSubnet(String ip) throws ProcessException {
        SubnetIPv6 subnet;
        String key = MAP.floorKey(expandIPv6(ip));
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
    
    private static synchronized TreeMap<String,SubnetIPv6> getMap() {
        TreeMap<String,SubnetIPv6> map = new TreeMap<String,SubnetIPv6>();
        map.putAll(MAP);
        return map;
    }
    
    /**
     * Armazenamento de cache em disco.
     */
    public static void store() {
        if (CHANGED) {
            try {
//                Server.logTrace("storing subnet6.map");
                long time = System.currentTimeMillis();
                TreeMap<String,SubnetIPv6> map = getMap();
                File file = new File("./data/subnet6.map");
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
    
    private static synchronized SubnetIPv6 put(String key, SubnetIPv6 subnet) {
        return MAP.put(key, subnet);
    }
    
    /**
     * Carregamento de cache do disco.
     */
    public static void load() {
        long time = System.currentTimeMillis();
        File file = new File("./data/subnet6.map");
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
                    if (value instanceof SubnetIPv6) {
                        SubnetIPv6 sub6 = (SubnetIPv6) value;
                        sub6.normalize();
                        String cidr = sub6.getInetnum();
                        String ip = getFirstIPv6(cidr);
                        String key = expandIPv6(ip);
                        put(key, sub6);
                    }
                }
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
    
    public int compareTo(SubnetIPv6 other) {
        return new Long(this.address).compareTo(other.address);
    }
    
    /**
     * Mapa completo dos blocos alocados aos países.
     */
    private static final TreeMap<String,SubnetIPv6> SERVER_MAP = new TreeMap<String,SubnetIPv6>();
    
    /**
     * Adiciona um servidor WHOIS na lista com seu respecitivo bloco.
     * @param inetnum o endereço de bloco em notação CIDR.
     * @param server o servidor WHOIS responsável por aquele bloco.
     */
    private static void addServer(String inetnum, String server) {
        try {
            SubnetIPv6 subnet = new SubnetIPv6(inetnum, server);
            String ip = getFirstIPv6(subnet.getInetnum());
            ip = expandIPv6(ip);
            SERVER_MAP.put(ip, subnet);
        } catch (Exception ex) {
            Server.logError(ex);
        }
    }
    
    // Temporário
    @Override
    public String getWhoisServer() throws ProcessException {
        String ip = getFirstIPv6(getInetnum());
        return getWhoisServer(ip);
    }
    
    /**
     * Retorna o servidor que possui a informação de bloco IPv6 de AS de um IP.
     * @param address endereço IP em inteiro de 64 bits.
     * @return o servidor que possui a informação de bloco IPv6 de AS de um IP.
     * @throws QueryException se o bloco não for encontrado para o IP especificado.
     */
    private static String getWhoisServer(String ip) throws ProcessException {
        // Busca eficiente O(log2(n)).
        ip = expandIPv6(ip);
        String key = SERVER_MAP.floorKey(ip);
        if (key == null) {
            throw new ProcessException("ERROR: SERVER NOT FOUND");
        } else {
            SubnetIPv6 subnet = SERVER_MAP.get(key);
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
        addServer("2001:1280::/25", Server.WHOIS_BR);
        addServer("2801:80::/26", Server.WHOIS_BR);
        addServer("2804::/16", Server.WHOIS_BR);
    }
}
