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
import java.io.BufferedReader;
import java.io.Serializable;
import java.io.StringReader;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.TreeSet;
import net.spfbl.data.Block;

/**
 * Representa o registro de bloco IP de uma subrede alocada 
 * para uma AS ou entidade de distribuição de blocos.
 * 
 * A chave primária é o atributo inetnum, 
 * que deve estar em notação CIDR sem abreviação.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public abstract class Subnet implements Serializable, Comparable<Subnet> {
    
    private static final long serialVersionUID = 1L;
    
    private String inetnum; // Chave primária com notação CIDR.
    private String inetnum_up;
    private String aut_num;
    private String abuse_c; // Código do responsável por abusos na rede.
    private String owner; // Nome do dono do bloco.
    private String ownerid; // Identificação do dono do bloco.
    private String responsible; // Responsável pelo bloco.
    private String country; // País onde o domínio foi registrado.
    private String owner_c; // Código do dono do bloco.
    private String tech_c; // Código do responsável técnico do bloco.
    private String inetrev;
    private Date created; // Data de criação do domínio pelo dono atual.
    private Date changed; // Data da alteração do registro do domínio.
    
    /**
     * Método temporário de correção.
     * Voltar o atibuto inetnum para final depois da transição.
     */
    protected void normalize() {
        this.inetnum = normalizeCIDR(inetnum);
    }
    
    /**
     * Lista dos servidores de nome do bloco.
     */
    private final ArrayList<String> nameServerList = new ArrayList<>();
    
    // Protected temporário até final da transição.
    protected String server = null; // Servidor onde a informação do bloco pode ser encontrada.
    private long lastRefresh = 0; // Última vez que houve atualização do registro em milisegundos.
    private boolean reduced = false; // Diz se a última consulta foi reduzida.
    private int queries = 1; // Contador de consultas.
    
    private static int REFRESH_TIME = 84; // Prazo máximo que o registro deve permanecer em cache em dias.
    
    /**
     * Atualiza o tempo de expiração do registro de bloco.
     * @param time tempo em dias que os registros de bloco devem ser atualizados.
     */
    public static void setRefreshTime(int time) {
        REFRESH_TIME = time;
    }
    
    protected Subnet(String result) throws ProcessException {
        // Associação da chave primária final.
        this.inetnum = normalizeCIDR(refresh(result));
    }
    
    protected boolean refresh() throws ProcessException {
        // Atualizando campos do registro.
        server = getWhoisServer(); // Temporário até final de transição.
        String result = Server.whois(inetnum, server);
        String inetnumResult = refresh(result);
        inetnumResult = normalizeCIDR(inetnumResult);
        return isInetnum(inetnumResult);
    }
    
    // Temporário até final da transição.
    public abstract String getWhoisServer() throws ProcessException;
    
    public static String getFirstIP(String cidr) {
        if (cidr == null) {
            return null;
        } else if (SubnetIPv4.isValidCIDRv4(cidr)) {
            return SubnetIPv4.getFirstIPv4(cidr);
        } else if (SubnetIPv6.isValidCIDRv6(cidr)) {
            return SubnetIPv6.getFirstIPv6(cidr);
        } else {
            return null;
        }
    }
    
    public static String getLastIP(String cidr) {
        if (cidr == null) {
            return null;
        } else if (SubnetIPv4.isValidCIDRv4(cidr)) {
            return SubnetIPv4.getLastIPv4(cidr);
        } else if (SubnetIPv6.isValidCIDRv6(cidr)) {
            return SubnetIPv6.getLastIPv6(cidr);
        } else {
            return null;
        }
    }
    
    public static String getPreviousIP(String ip) {
        if (ip == null) {
            return null;
        } else if (SubnetIPv4.isValidIPv4(ip)) {
            return SubnetIPv4.getPreviousIPv4(ip);
        } else if (SubnetIPv6.isValidIPv6(ip)) {
            return SubnetIPv6.getPreviousIPv6(ip);
        } else {
            return null;
        }
    }
    
    public static String getNextIP(String ip) {
        if (ip == null) {
            return null;
        } else if (SubnetIPv4.isValidIPv4(ip)) {
            return SubnetIPv4.getNextIPv4(ip);
        } else if (SubnetIPv6.isValidIPv6(ip)) {
            return SubnetIPv6.getNextIPv6(ip);
        } else {
            return null;
        }
    }
    
    public static short getMask(String cidr) {
        if (cidr == null) {
            return 0;
        } else if (cidr.contains("/")) {
            try {
                int index = cidr.lastIndexOf('/') + 1;
                String number = cidr.substring(index);
                return Short.parseShort(number);
            } catch (NumberFormatException ex) {
                return 0;
            }
        } else {
            return 0;
        }
    }
    
    public static String normalizeCIDR(String cidr) {
        if (cidr == null) {
            return null;
        } else if (SubnetIPv4.isValidCIDRv4(cidr)) {
            return SubnetIPv4.normalizeCIDRv4(cidr);
        } else if (SubnetIPv6.isValidCIDRv6(cidr)) {
            return SubnetIPv6.normalizeCIDRv6(cidr);
        } else if (cidr.contains(".")) {
            return SubnetIPv4.normalizeCIDRv4(cidr);
        } else if (cidr.contains(":")) {
            return SubnetIPv6.normalizeCIDRv6(cidr);
        } else {
            return cidr;
        }
    }
    
    public static String normalizeIP(String ip) {
        if (ip == null) {
            return null;
        } else if (SubnetIPv4.isValidIPv4(ip)) {
            return SubnetIPv4.normalizeIPv4(ip);
        } else if (SubnetIPv6.isValidIPv6(ip)) {
            return SubnetIPv6.normalizeIPv6(ip);
        } else {
            return null;
        }
    }
    
    public static String expandIP(String ip) {
        if (ip == null) {
            return null;
        } else if (SubnetIPv4.isValidIPv4(ip)) {
            return SubnetIPv4.expandIPv4(ip);
        } else if (SubnetIPv6.isValidIPv6(ip)) {
            return SubnetIPv6.expandIPv6(ip);
        } else {
            return ip;
        }
    }
    
    public static String expandCIDR(String cidr) {
        if (cidr == null) {
            return null;
        } else if (SubnetIPv4.isValidCIDRv4(cidr)) {
            return SubnetIPv4.expandCIDRv4(cidr);
        } else if (SubnetIPv6.isValidCIDRv6(cidr)) {
            return SubnetIPv6.expandCIDRv6(cidr);
        } else {
            return cidr;
        }
    }
    
    public abstract Subnet drop();
    
    /**
     * Atualiza os campos do registro com resultado do WHOIS.
     * @param result o resultado do WHOIS.
     * @return o endereçoamento CIDR apresentado no resultado do WHOIS.
     * @throws QueryException se houver alguma falha da atualização do registro.
     */
    private String refresh(String result) throws ProcessException {
        try {
            String inetnum_upNew = null;
            String aut_numNew = null;
            String abuse_cNew = null;
            String ownerNew = null;
            String owneridNew = null;
            String responsibleNew = null;
            String countryNew = null;
            String owner_cNew = null;
            String tech_cNew = null;
            String inetrevNew = null;
            Date createdNew = null;
            Date changedNew = null;
            ArrayList<String> nameServerListNew = new ArrayList<>();
            boolean reducedNew = false;
            String inetnumResult = null;
            SimpleDateFormat dateFormatter = new SimpleDateFormat("yyyyMMdd");
            try (BufferedReader reader = new BufferedReader(new StringReader(result))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.startsWith("inetnum:")) {
                        int index = line.indexOf(':') + 1;
                        inetnumResult = line.substring(index).trim();
                    } else if (line.startsWith("inetnum-up:")) {
                        int index = line.indexOf(':') + 1;
                        inetnum_upNew = line.substring(index).trim();
                    } else if (line.startsWith("aut-num:")) {
                        int index = line.indexOf(':') + 1;
                        aut_numNew = line.substring(index).trim();
                    } else if (line.startsWith("abuse-c:")) {
                        int index = line.indexOf(':') + 1;
                        abuse_cNew = line.substring(index).trim();
                    } else if (line.startsWith("owner:")) {
                        int index = line.indexOf(':') + 1;
                        ownerNew = line.substring(index).trim();
                    } else if (line.startsWith("ownerid:")) {
                        int index = line.indexOf(':') + 1;
                        owneridNew = line.substring(index).trim();
                    } else if (line.startsWith("responsible:")) {
                        int index = line.indexOf(':') + 1;
                        responsibleNew = line.substring(index).trim();
                    } else if (line.startsWith("country:")) {
                        int index = line.indexOf(':') + 1;
                        countryNew = line.substring(index).trim();
                    } else if (line.startsWith("owner-c:")) {
                        int index = line.indexOf(':') + 1;
                        owner_cNew = line.substring(index).trim();
                    } else if (line.startsWith("tech-c:")) {
                        int index = line.indexOf(':') + 1;
                        owner_cNew = line.substring(index).trim();
                    } else if (line.startsWith("inetrev:")) {
                        int index = line.indexOf(':') + 1;
                        String inetrevResult = line.substring(index).trim();
                        inetrevNew = inetrevResult;
                    } else if (line.startsWith("nserver:")) {
                        int index = line.indexOf(':') + 1;
                        String nserver = line.substring(index).trim();
                        line = reader.readLine().trim();
                        index = line.indexOf(':') + 1;
                        String nsstat = line.substring(index).trim();
                        line = reader.readLine().trim();
                        index = line.indexOf(':') + 1;
                        String nslastaa = line.substring(index).trim();
                        NameServer ns = NameServer.getNameServer(nserver);
                        ns.setStat(nsstat);
                        ns.setLastAA(nslastaa);
                        nameServerListNew.add(nserver);
                    } else if (line.startsWith("created:")) {
                        int index = line.indexOf(':') + 1;
                        String valor = line.substring(index).trim();
                        if (valor.startsWith("before ")) {
                            index = line.indexOf(' ') - 1;
                            valor = valor.substring(index);
                        }
                        if (valor.length() > 7) {
                            valor = valor.substring(0, 8);
                            createdNew = dateFormatter.parse(valor);
                        }
                    } else if (line.startsWith("changed:")) {
                        int index = line.indexOf(':') + 1;
                        String valor = line.substring(index).trim();
                        if (valor.length() > 7) {
                            valor = valor.substring(0, 8);
                            changedNew = dateFormatter.parse(valor);
                        }
                    } else if (line.startsWith("nic-hdl-br:")) {
                        try {
                            String person = null;
                            String e_mail = null;
                            String created2 = null;
                            String changed2 = null;
                            String provider2 = null;
                            String country2 = null;
                            int index = line.indexOf(':') + 1;
                            String nic_hdl_br = line.substring(index).trim();
                            while ((line = reader.readLine().trim()).length() > 0) {
                                index = line.indexOf(':') + 1;
                                if (line.startsWith("person:")) {
                                    person = line.substring(index).trim();
                                } else if (line.startsWith("e-mail:")) {
                                    e_mail = line.substring(index).trim();
                                } else if (line.startsWith("created:")) {
                                    created2 = line.substring(index).trim();
                                } else if (line.startsWith("changed:")) {
                                    changed2 = line.substring(index).trim();
                                } else if (line.startsWith("provider:")) {
                                    provider2 = line.substring(index).trim();
                                } else if (line.startsWith("country:")) {
                                    country2 = line.substring(index).trim();
                                } else {
                                    Server.logError("Linha não reconhecida: " + line);
                                }
                            }
                            Handle handle = Handle.getHandle(nic_hdl_br);
                            handle.setPerson(person);
                            handle.setEmail(e_mail);
                            handle.setCreated(created2);
                            handle.setChanged(changed2);
                            handle.setProvider(provider2);
                            handle.setCountry(country2);
                        } catch (ProcessException ex) {
                            Server.logError(ex);
                        }
                    } else if (line.startsWith("% Not assigned.")) {
                        throw new ProcessException("ERROR: SUBNET NOT ASSIGNED");
                    } else if (line.startsWith("% Permission denied.")) {
                        throw new ProcessException("ERROR: WHOIS DENIED");
                    } else if (line.startsWith("% Permissão negada.")) {
                        throw new ProcessException("ERROR: WHOIS DENIED");
                    } else if (line.startsWith("% Query rate limit exceeded. Reduced information.")) {
                        // Informação reduzida devido ao estouro de limite de consultas.
                        Server.removeWhoisQueryHour();
                        reducedNew = true;
                    } else if (line.startsWith("% Query rate limit exceeded")) {
                        // Restrição total devido ao estouro de limite de consultas.
                        Server.removeWhoisQueryDay();
                        throw new ProcessException("ERROR: WHOIS QUERY LIMIT");
                    } else if (line.startsWith("% Maximum concurrent connections limit exceeded")) {
                        throw new ProcessException("ERROR: WHOIS CONNECTION LIMIT");
                    } else if (line.length() > 0 && Character.isLetter(line.charAt(0))) {
                        Server.logError("Linha não reconhecida: " + line);
                    }
                }
            }
            if (inetnumResult == null) {
                throw new ProcessException("ERROR: SUBNET NOT FOUND");
            } else {
                this.inetnum_up = inetnum_upNew;
                this.aut_num = aut_numNew;
                this.abuse_c = abuse_cNew;
                this.owner = ownerNew;
                if (owneridNew != null) {
                    // Associar ownerid somente se retornar valor.
                    this.ownerid = owneridNew;
                }
                this.responsible = responsibleNew;
                this.country = countryNew;
                this.owner_c = owner_cNew;
                this.tech_c = tech_cNew;
                this.inetrev = inetrevNew;
                this.created = createdNew;
                this.changed = changedNew;
                this.nameServerList.clear();
                this.nameServerList.addAll(nameServerListNew);
                this.reduced = reducedNew;
                this.lastRefresh = System.currentTimeMillis();
                this.queries = 1;
                return inetnumResult;
            }
        } catch (ProcessException ex) {
            throw ex;
        } catch (Exception ex) {
            Server.logError(ex);
            throw new ProcessException("ERROR: PARSING", ex);
        }
    }
    
    protected Subnet(String inetnum, String server) {
        // Associação da chave primária final.
        this.inetnum = normalizeCIDR(inetnum);
        // Associação do servdidor do resultado.
        this.server = server;
    }
    
    /**
     * Verifica se o registro atual expirou.
     * @return verdadeiro se o registro atual expirou.
     */
    public boolean isRegistryExpired() {
        long expiredTime = (System.currentTimeMillis() - lastRefresh) / Server.DAY_TIME;
        return expiredTime > REFRESH_TIME;
    }
    
    /**
     * Verifica se o registro atual expirou três dia.
     * @return verdadeiro se o registro atual expirou três dia.
     */
    public boolean isRegistryExpired3() {
        long expiredTime = (System.currentTimeMillis() - lastRefresh) / Server.DAY_TIME;
        return expiredTime > 3;
    }
    
    /**
     * Verifica se o registro atual está com informação reduzida.
     * @return verdadeiro se o registro atual com informação reduzida.
     */
    public boolean isReduced() {
        return reduced;
    }
    
    public Owner getOwner() throws ProcessException {
        return Owner.getOwner(ownerid);
    }
    
    public Handle getAbuseHandle() {
        return Handle.getHandle(abuse_c);
    }
    
    public Handle getOwnerHandle() {
        return Handle.getHandle(owner_c);
    }
    
    public Handle getTechHandle() {
        return Handle.getHandle(tech_c);
    }
    
    /**
     * Retorna o bloco IP na notação CIDR.
     * @return o bloco IP na notação CIDR.
     */
    public String getInetnum() {
        return inetnum;
    }
    
    public boolean isInetnum(String inetnum) {
        if (inetnum == null) {
            return false;
        } else {
            return inetnum.equals(this.inetnum);
        }
    }
    
    /**
     * Retorna o país onde o bloco foi alocado.
     * @return o país onde o bloco foi alocado.
     */
    public String getCountry() {
        return country;
    }
    
    public AutonomousSystem getAS() throws ProcessException {
        return AutonomousSystem.getAS(aut_num, getServer());
    }
    
    /**
     * Retorna o servidor que possui a informação de blocos de AS.
     * @return o servidor que possui a informação de blocos de AS.
     * @throws ProcessException se houver falha no processamento.
     */
    public String getServer() throws ProcessException {
        if (server == null) {
            return server = getWhoisServer();
        } else {
            return server;
        }
    }
    
    public static String getValue(String address, String key) {
        if (address == null || key == null) {
            return null;
        } else if (Subnet.isValidIP(address)) {
            try {
                Subnet subnet = Subnet.getSubnet(address);
                if (subnet == null) {
                    return null;
                } else {
                    return subnet.get(key, false);
                }
            } catch (ProcessException ex) {
                if (ex.getMessage().equals("ERROR: NSLOOKUP")) {
                    return null;
                } else if (ex.getMessage().equals("ERROR: WHOIS QUERY LIMIT")) {
                    return null;
                } else if (ex.getMessage().equals("ERROR: DOMAIN NOT FOUND")) {
                    return null;
                } else if (ex.getMessage().equals("ERROR: WHOIS QUERY LIMIT")) {
                    return null;
                } else if (ex.getMessage().equals("ERROR: SERVER NOT FOUND")) {
                    return null;
                } else {
                    Server.logError(ex);
                    return null;
                }
            }
        } else {
            return null;
        }
    }
    
    public static String getBlock(String ip) {
        if (SubnetIPv4.isValidIPv4(ip)) {
            return SubnetIPv4.getInetnum(ip);
        } else if (SubnetIPv6.isValidIPv6(ip)) {
            return SubnetIPv6.getInetnum(ip);
        } else {
            return null;
        }
    }
    
    public static String getOwnerID(String ip) {
        if (SubnetIPv4.isValidIPv4(ip)) {
            return SubnetIPv4.getOwnerID(ip);
        } else if (SubnetIPv6.isValidIPv6(ip)) {
            return SubnetIPv6.getOwnerID(ip);
        } else {
            return null;
        }
    }
    
    public static String getInetnum(String ip) {
        if (SubnetIPv4.isValidIPv4(ip)) {
            return SubnetIPv4.getInetnum(ip);
        } else if (SubnetIPv6.isValidIPv6(ip)) {
            return SubnetIPv6.getInetnum(ip);
        } else {
            return null;
        }
    }
    
    public static String getOwnerC(String ip) {
        if (SubnetIPv4.isValidIPv4(ip)) {
            return SubnetIPv4.getOwnerC(ip);
        } else if (SubnetIPv6.isValidIPv6(ip)) {
            return SubnetIPv6.getOwnerC(ip);
        } else {
            return null;
        }
    }
    
    public static String reverse(String ip) {
        if (SubnetIPv4.isValidIPv4(ip)) {
            return SubnetIPv4.reverse(ip);
        } else if (SubnetIPv6.isValidIPv6(ip)) {
            return SubnetIPv6.reverse(ip);
        } else {
            return null;
        }
    }
    
    public static boolean isValidCIDR(String cidr) {
        if (SubnetIPv4.isValidCIDRv4(cidr)) {
            return true;
        } else if (SubnetIPv6.isValidCIDRv6(cidr)) {
            return true;
        } else {
            return false;
        }
    }
    
    /**
     * Verifica se um IP é válido na notação de IP.
     * @param ip o IP a ser verificado.
     * @return verdadeiro se um IP é válido.
     */
    public static boolean isValidIP(String ip) {
        if (SubnetIPv4.isValidIPv4(ip)) {
            return true;
        } else if (SubnetIPv6.isValidIPv6(ip)) {
            return true;
        } else {
            return false;
        }
    }
    
    public static boolean isReservedIP(String ip) {
        if (SubnetIPv4.isValidIPv4(ip)) {
            return SubnetIPv4.isReservedIPv4(ip);
        } else if (SubnetIPv6.isValidIPv6(ip)) {
            return SubnetIPv6.isReservedIPv6(ip);
        } else {
            return false;
        }
    }
    

    
    public static String splitCIDR(String cidr) {
        String result = "";
        String first = Subnet.getFirstIP(cidr);
        String last = Subnet.getLastIP(cidr);
        short mask = Subnet.getMask(cidr);
        int max = SubnetIPv4.isValidIPv4(first) ? 32 : 64;
        if (mask < max) {
            mask++;
            String cidr1 = first + "/" + mask;
            String cidr2 = last + "/" + mask;
            cidr1 = Subnet.normalizeCIDR(cidr1);
            cidr2 = Subnet.normalizeCIDR(cidr2);
            try {
                if (Block.add(cidr1) == null) {
                    result += "EXISTS " + cidr1 + "\n";
                } else {
                    result += "ADDED " + cidr1 + "\n";
                }
            } catch (ProcessException ex) {
                result += splitCIDR(cidr1);
            }
            try {
                if (Block.add(cidr2) == null) {
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
    
    public static Subnet getSubnet(String ip) throws ProcessException {
        if (SubnetIPv4.isValidIPv4(ip)) {
            Subnet subnet = SubnetIPv4.getSubnet(ip);
            subnet.queries++;
            return subnet;
        } else if (SubnetIPv6.isValidIPv6(ip)) {
            Subnet subnet = SubnetIPv6.getSubnet(ip);
            subnet.queries++;
            return subnet;
        } else {
            throw new ProcessException("ERROR: INVALID IP");
        }
    }
    
    private static TreeSet<Subnet> getSubnetSet() {
        TreeSet<Subnet> subnetSet = new TreeSet<>();
        subnetSet.addAll(SubnetIPv4.getSubnetSet());
        subnetSet.addAll(SubnetIPv6.getSubnetSet());
        return subnetSet;
    }
    
    /**
     * Atualiza em background todos os registros adicionados no conjunto.
     */
    public static boolean backgroundRefresh() {
        Subnet subnetMax = null;
        for (Subnet subnet : getSubnetSet()) {
            if (subnet.isReduced() || subnet.isRegistryExpired()) {
                if (subnet.queries > 3) {
                    if (subnetMax == null) {
                        subnetMax = subnet;
                    } else if (subnetMax.queries < subnet.queries) {
                        subnetMax = subnet;
                    } else if (subnetMax.lastRefresh > subnet.lastRefresh) {
                        subnetMax = subnet;
                    }
                }
            }
        }
        if (subnetMax == null) {
            return false;
        } else {
            try {
                // Atualizando campos do registro.
                return subnetMax.refresh();
            } catch (ProcessException ex) {
                if (ex.isErrorMessage("WHOIS QUERY LIMIT")) {
                    // Fazer nada.
                } else if (ex.isErrorMessage("WHOIS CONNECTION FAIL")) {
                    // Fazer nada.
                } else if (ex.isErrorMessage("TOO MANY CONNECTIONS")) {
                    // Fazer nada.
                } else if (ex.isErrorMessage("SUBNET NOT ASSIGNED")) {
                    subnetMax.drop();
                } else {
                    Server.logError(ex);
                }
                return false;
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        }
    }
    
    /**
     * Retorna o valor de um campo do registro ou o valor de uma função.
     * @param key o campo do registro cujo valor deve ser retornado.
     * @return o valor de um campo do registro ou o valor de uma função.
     * @throws ProcessException se houver falha no processamento.
     */
    public String get(String key, boolean updated) throws ProcessException  {
        if (key.equals("inetnum")) {
            return inetnum;
        } else if (key.equals("inetnum-up")) {
            return inetnum_up;
        } else if (key.equals("aut-num")) {
            return aut_num;
        } else if (key.equals("abuse-c")) {
            return abuse_c;
        } else if (key.equals("owner")) {
            return owner;
        } else if (reduced && updated) {
            // Ultima consulta expirada.
            // Demais campos estão comprometidos.
            throw new ProcessException("ERROR: WHOIS QUERY LIMIT");
        } else if (key.equals("ownerid")) {
            return ownerid;
        } else if (key.equals("responsible")) {
            return responsible;
        } else if (key.equals("country")) {
            return country;
        } else if (key.equals("owner-c")) {
            return owner_c;
        } else if (key.equals("tech-c")) {
            return tech_c;
        } else if (key.equals("inetrev")) {
            return inetrev;
        } else if (key.equals("created")) {
            if (created == null) {
                return null;
            } else {
                return new SimpleDateFormat("yyyyMMdd").format(created);
            }
        } else if (key.equals("changed")) {
            if (changed == null) {
                return null;
            } else {
                return new SimpleDateFormat("yyyyMMdd").format(changed);
            }
        } else if (key.equals("nserver")) {
            return nameServerList.toString();
        } else if (key.startsWith("aut-num/")) {
            int index = key.indexOf('/') + 1;
            key = key.substring(index);
            return getAS().get(key);
        } else if (key.startsWith("owner/")) {
            int index = key.indexOf('/') + 1;
            key = key.substring(index);
            Owner ownerLocal = getOwner();
            if (ownerLocal == null) {
                return null;
            } else {
                return ownerLocal.get(key, updated);
            }
        } else if (key.startsWith("abuse-c/")) {
            int index = key.indexOf('/') + 1;
            key = key.substring(index);
            Handle abuse = getAbuseHandle();
            if (abuse == null) {
                return null;
            } else {
                return abuse.get(key);
            }
        } else if (key.startsWith("owner-c/")) {
            int index = key.indexOf('/') + 1;
            key = key.substring(index);
            Handle owner = getOwnerHandle();
            if (owner == null) {
                return null;
            } else {
                return owner.get(key);
            }
        } else if (key.startsWith("tech-c/")) {
            int index = key.indexOf('/') + 1;
            key = key.substring(index);
            Handle tech = getTechHandle();
            if (tech == null) {
                return null;
            } else {
                return tech.get(key);
            }
        } else if (key.startsWith("nserver/")) {
            int index = key.indexOf('/') + 1;
            key = key.substring(index);
            TreeSet<String> resultSet = new TreeSet<>();
            for (String nserver : nameServerList) {
                NameServer nameServer = NameServer.getNameServer(nserver);
                String result = nameServer.get(key);
                resultSet.add(nserver + "=" + result);
            }
            return resultSet.toString();
        } else {
            return null;
        }
    }
    
    public static boolean containsIP(String cidr, String ip) {
        if (SubnetIPv4.containsIPv4(cidr, ip)) {
            return true;
        } else if (SubnetIPv6.containsIPv6(cidr, ip)) {
            return true;
        } else {
            return false;
        }
    }
    
    @Override
    public boolean equals(Object other) {
        if (other instanceof Subnet) {
            return equals((Subnet) other);
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return inetnum.hashCode();
    }
    
    /**
     * Verifica se o registro atual é o mesmo de outro.
     * @param other o outro registro a ser comparado.
     * @return verdadeiro se o registro passado é igual ao atual.
     */
    public boolean equals(Subnet other) {
        if (other == null) {
            return false;
        } else {
            return this.inetnum.equals(other.inetnum);
        }
    }
    
    @Override
    public String toString() {
        return inetnum;
    }

    @Override
    public int compareTo(Subnet other) {
        if (this instanceof SubnetIPv4) {
            if (other instanceof SubnetIPv4) {
                return ((SubnetIPv4)this).compareTo((SubnetIPv4)other);
            } else {
                return -1;
            }
        } else if (this instanceof SubnetIPv6) {
            if (other instanceof SubnetIPv6) {
                return ((SubnetIPv6)this).compareTo((SubnetIPv6)other);
            } else {
                return 1;
            }
        } else {
            return 0;
        }
    }
}
