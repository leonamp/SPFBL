/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.com.allchemistry.whois;

import br.com.allchemistry.core.Server;
import br.com.allchemistry.core.ProcessException;
import java.io.BufferedReader;
import java.io.Serializable;
import java.io.StringReader;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.TreeSet;

/**
 * Representa o registro de bloco IP de uma subrede alocada 
 * para uma AS ou entidade de distribuição de blocos.
 * 
 * A chave primária é o atributo inetnum, 
 * que deve estar em notação CIDR sem abreviação.
 * 
 * @author Leandro Carlos Rodrigues <leandro@allchemistry.com.br>
 */
public abstract class Subnet implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private final String inetnum; // Chave primária com notação CIDR.
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
     * Lista dos servidores de nome do bloco.
     */
    private final ArrayList<String> nameServerList = new ArrayList<String>();
    
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
    
    /**
     * Formatação padrão dos campos de data do WHOIS.
     */
    private static final SimpleDateFormat DATE_FORMATTER = new SimpleDateFormat("yyyyMMdd");
    
    protected Subnet(String result) throws ProcessException {
        // Associação da chave primária final.
        this.inetnum = refresh(result);
    }
    
    protected boolean refresh() throws ProcessException {
        // Atualizando campos do registro.
        server = getWhoisServer(); // Temporário até final de transição.
        String result = Server.whois(inetnum, server);
        String inetnumResult = refresh(result);
        return isInetnum(inetnumResult);
    }
    
    // Temporário até final da transição.
    public abstract String getWhoisServer() throws ProcessException;
    
    public static String correctIP(String ip) {
        if (SubnetIPv4.isValidIPv4(ip)) {
            return SubnetIPv4.correctIP(ip);
        } else if (SubnetIPv6.isValidIPv6(ip)) {
            return SubnetIPv6.correctIP(ip);
        } else {
            return ip;
        }
    }
    
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
            ArrayList<String> nameServerListNew = new ArrayList<String>();
            boolean reducedNew = false;
            String inetnumResult = null;
            BufferedReader reader = new BufferedReader(new StringReader(result));
            try {
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
                        createdNew = DATE_FORMATTER.parse(line.substring(index).trim());
                    } else if (line.startsWith("changed:")) {
                        int index = line.indexOf(':') + 1;
                        changedNew = DATE_FORMATTER.parse(line.substring(index).trim());
                    } else if (line.startsWith("nic-hdl-br:")) {
                        int index = line.indexOf(':') + 1;
                        String nic_hdl_br = line.substring(index).trim();
                        line = reader.readLine().trim();
                        index = line.indexOf(':') + 1;
                        String person = line.substring(index).trim();
                        line = reader.readLine().trim();
                        index = line.indexOf(':') + 1;
                        String e_mail;
                        if (reducedNew) {
                            e_mail = null;
                        } else {
                            e_mail = line.substring(index).trim();
                            line = reader.readLine().trim();
                            index = line.indexOf(':') + 1;
                        }
                        String created2 = line.substring(index).trim();
                        line = reader.readLine().trim();
                        index = line.indexOf(':') + 1;
                        String changed2 = line.substring(index).trim();
                        Handle handle = Handle.getHandle(nic_hdl_br);
                        handle.setPerson(person);
                        handle.setEmail(e_mail);
                        handle.setCreated(created2);
                        handle.setChanged(changed2);
                    } else if (line.startsWith("% Query rate limit exceeded. Reduced information.")) {
                        // Informação reduzida devido ao estouro de limite de consultas.
                        reducedNew = true;
                    } else if (line.startsWith("% Permission denied.")) {
                        throw new ProcessException("ERROR: WHOIS DENIED");
                    } else if (line.startsWith("% Permissão negada.")) {
                        throw new ProcessException("ERROR: WHOIS DENIED");
                    } else if (line.startsWith("% Maximum concurrent connections limit exceeded")) {
                        throw new ProcessException("ERROR: WHOIS CONCURRENT");
                    } else if (line.length() > 0 && Character.isLetter(line.charAt(0))) {
                        Server.logError("Linha não reconhecida: " + line);
                    }
                }
            } finally {
                reader.close();
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
        this.inetnum = inetnum;
        // Associação do servdidor do resultado.
        this.server = server;
    }
    
    /**
     * Verifica se o registro atual expirou.
     * @return verdadeiro se o registro atual expirou.
     */
    public boolean isRegistryExpired() {
        int expiredTime = (int) (System.currentTimeMillis() - lastRefresh) / Server.DAY_TIME;
        return expiredTime > REFRESH_TIME;
    }
    
//    /**
//     * Verifica se o registro atual está quase expirando.
//     * @return verdadeiro se o registro atual está quase expirando.
//     */
//    public boolean isRegistryAlmostExpired() {
//        int expiredTime = (int) (System.currentTimeMillis() - lastRefresh) / Server.DAY_TIME;
//        return expiredTime > (2 * REFRESH_TIME / 3); // Dois terços antes da expiração.
//    }
    
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
    
    public static String getOwnerID(String ip) {
        if (SubnetIPv4.isValidIPv4(ip)) {
            return SubnetIPv4.getOwnerID(ip);
        } else if (SubnetIPv6.isValidIPv6(ip)) {
            return SubnetIPv6.getOwnerID(ip);
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
    
    private static synchronized TreeSet<Subnet> getSubnetSet() {
        TreeSet<Subnet> subnetSet = new TreeSet<Subnet>();
        subnetSet.addAll(SubnetIPv4.getSubnetSet());
        subnetSet.addAll(SubnetIPv6.getSubnetSet());
        return subnetSet;
    }
    
    /**
     * Atualiza em background todos os registros adicionados no conjunto.
     */
    public static synchronized boolean backgroundRefresh() {
        Subnet subnetMax = null;
        for (Subnet subnet : getSubnetSet()) {
            if (subnet.reduced || subnet.queries > 3) {
                if (subnetMax == null) {
                    subnetMax = subnet;
                } else if (subnetMax.queries < subnet.queries) {
                    subnetMax = subnet;
                } else if (subnetMax.lastRefresh > subnet.lastRefresh) {
                    subnetMax = subnet;
                }
            }
        }
        if (subnetMax == null) {
            return false;
        } else {
            try {
                // Atualizando campos do registro.
                return subnetMax.refresh();
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
                return DATE_FORMATTER.format(created);
            }
        } else if (key.equals("changed")) {
            if (changed == null) {
                return null;
            } else {
                return DATE_FORMATTER.format(changed);
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
            return getOwner().get(key, updated);
        } else if (key.startsWith("abuse-c/")) {
            int index = key.indexOf('/') + 1;
            key = key.substring(index);
            return getAbuseHandle().get(key);
        } else if (key.startsWith("owner-c/")) {
            int index = key.indexOf('/') + 1;
            key = key.substring(index);
            return getOwnerHandle().get(key);
        } else if (key.startsWith("tech-c/")) {
            int index = key.indexOf('/') + 1;
            key = key.substring(index);
            return getTechHandle().get(key);
        } else if (key.startsWith("nserver/")) {
            int index = key.indexOf('/') + 1;
            key = key.substring(index);
            TreeSet<String> resultSet = new TreeSet<String>();
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
}
