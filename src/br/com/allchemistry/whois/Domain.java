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
package br.com.allchemistry.whois;

import br.com.allchemistry.core.Server;
import br.com.allchemistry.core.ProcessException;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.Serializable;
import java.io.StringReader;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.TreeSet;
import java.util.regex.Pattern;
import javax.naming.CommunicationException;
import javax.naming.NameNotFoundException;
import javax.naming.ServiceUnavailableException;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Representa o registro de domínio de um resultado WHOIS.
 * 
 * A chave primária dos registros é o atributo domain.
 * 
 * <h2>Mecanismo de busca</h2>
 * A busca no cache é realizada com esta chave. 
 * Porém é possível buscar um registro de domínio pelo host.
 * Caso o TLD do domínio seja conhecido, 
 * o host é convertido em domínio e a busca é realizada em O(1).
 * Caso o TLD do host não seja conhecido,
 * Uma consulta no WHOIS é realizada pelo, 
 * onde o mesmo retorna o registro do domínio correto.
 * Com posse deste domínio correto, 
 * o novo TLD é encontrado e adicionado no conjunto de TLDs conhecidos.
 * O mecanismo é totalmente automático, portanto não existe 
 * necessidade de manter e administrar uma lista de TLDs manualmente.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Domain implements Serializable, Comparable<Domain> {
    
    private static final long serialVersionUID = 1L;
    
    public final String domain; // Domínio real indicado pelo WHOIS.
    public String owner; // Nome do dono do domínio.
    public String ownerid; // Identificação do dono do domínio.
    public String responsible; // Responsável pelo domínio.
    public String country; // País onde o domínio foi registrado.
    public String owner_c; // Código do dono do domínio.
    public String admin_c; // Código do administrador do domínio.
    public String tech_c; // Código do responsável técnico do domínio.
    public String billing_c; // Código do responsável pelos pagamentos do domínio.
    public Date created; // Data de criação do domínio pelo dono atual.
    public Date expires; // Data de expiração do registro do domínio.
    public Date changed; // Data da alteração do registro do domínio.
    public String provider; // Provedor de acesso do domínio.
    public String status; // Status atual do domínio.
    public String dsrecord;
    public String dsstatus;
    public String dslastok;
    public String saci;
    public String web_whois;
    
    /**
     * Lista dos servidores de nome do domínio.
     */
    public final ArrayList<String> nameServerList = new ArrayList<String>();
    
    public String server = null; // Servidor onde a informação do domínio pode ser encontrada.
    public long lastRefresh = 0; // Última vez que houve atualização do registro em milisegundos.
    public boolean reduced = false; // Diz se a última consulta foi reduzida.
    public int queries = 1; // Contador de consultas.
    
    private static int REFRESH_TIME = 21;  // Prazo máximo que o registro deve permanecer em cache em dias.
    
    /**
     * Formatação padrão dos campos de data do WHOIS.
     */
    public static final SimpleDateFormat DATE_FORMATTER = new SimpleDateFormat("yyyyMMdd");
    
    /**
     * Atualiza o tempo de expiração do registro de domínio.
     * @param time tempo em dias que os registros de domíno devem ser atualizados.
     */
    public static void setRefreshTime(int time) {
        REFRESH_TIME = time;
    }
    
    /**
     * Verifica se o registro atual expirou.
     * @return verdadeiro se o registro atual expirou.
     */
    public boolean isRegistryExpired() {
        int expiredTime = (int) (System.currentTimeMillis() - lastRefresh) / Server.DAY_TIME;
        return expiredTime > REFRESH_TIME;
    }
    
    /**
     * Verifica se o registro atual expirou três dia.
     * @return verdadeiro se o registro atual expirou três dia.
     */
    public boolean isRegistryExpired3() {
        int expiredTime = (int) (System.currentTimeMillis() - lastRefresh) / Server.DAY_TIME;
        return expiredTime > 3;
    }
    
//    /**
//     * Verifica se o registro atual está quase expirando.
//     * @return verdadeiro se o registro atual está quase expirando.
//     */
//    public boolean isRegistryAlmostExpired() {
//        int expiredTime = (int) (System.currentTimeMillis() - lastRefresh) / Server.DAY_TIME;
//        return expiredTime > (2 * REFRESH_TIME / 3); // Dois terços da expiração.
//    }
    
    /**
     * Verifica se o registro atual está com informação reduzida.
     * @return verdadeiro se o registro atual com informação reduzida.
     */
    public boolean isReduced() {
        return reduced;
    }
    
    /**
     * Extrai o host de um endereço de e-mail.
     * @param address o endereço que contém o host.
     * @param arroba se o arroba deve ser mantido na resposta.
     * @return o host do endereço de e-mail.
     */
    public static String extractHost(String address, boolean pontuacao) {
        if (address == null) {
            return null;
        } else if (address.length() == 0) {
            return null;
        } else if (address.contains("@")) {
            // O endereço é um e-mail.
            // Extrair a parte do host.
            int index = address.indexOf('@');
            if (!pontuacao) {
                index++;
            }
            return address.substring(index).toLowerCase();
        } else if (pontuacao && !address.startsWith(".")) {
            return "." + address.toLowerCase();
        } else if (pontuacao && address.startsWith(".")) {
            return address.toLowerCase();
        } else if (!pontuacao && !address.startsWith(".")) {
            return address.toLowerCase();
        } else{
            return address.substring(1).toLowerCase();
        }
    }
    
    /**
     * Extrai o domínio pelos TLDs conhecidos.
     * @param address o endereço que contém o domínio.
     * @param se o ponto deve ser mantido na resposta.
     * @return o domínio pelos TLDs conhecidos.
     * @throws ProcessException se o endereço for um TLD.
     */
    public static String extractDomain(String address,
            boolean pontuacao) throws ProcessException {
        address = "." + extractHost(address, false);
        if (TLD_SET.contains(address)) {
            throw new ProcessException("ERROR: RESERVED");
        } else {
            int lastIndex = address.length() - 1;
            int beginIndex = 1;
            while (beginIndex < lastIndex) {
                int endIndex = address.indexOf('.', beginIndex);
                if (endIndex == -1) {
                    break;
                } else {
                    String tld = address.substring(endIndex);
                    if (TLD_SET.contains(tld)) {
                        if (pontuacao) {
                            return address.substring(beginIndex-1);
                        } else {
                            return address.substring(beginIndex);
                        }
                    }
                    beginIndex = endIndex + 1;
                }
            }
            if (pontuacao) {
                return address;
            } else {
                return address.substring(1);
            }
        }
    }
    
    /**
     * Extrai o TLD do endereço.
     * @param address o endereço que contém o TLD.
     * @throws se o ponto de ser mantido.
     * @return o TLDs do endereço.
     * @throws se houve faha na extração do domínio.
     */
    public static String extractTLD(String address,
            boolean ponto) throws ProcessException {
        int lastIndex = address.length() - 1;
        int beginIndex = 0;
        while (beginIndex < lastIndex) {
            int endIndex = address.indexOf('.', beginIndex);
            if (endIndex == -1) {
                break;
            } else {
                String tld = address.substring(endIndex);
                if (TLD_SET.contains(tld)) {
                    if (ponto) {
                        return tld;
                    } else {
                        return tld.substring(1);
                    }
                }
                beginIndex = endIndex + 1;
            }
        }
        beginIndex = address.lastIndexOf('.');
        if (ponto) {
            return address.substring(beginIndex-1);
        } else {
            return address.substring(beginIndex);
        }
    }
    
    /**
     * Verifica se o endereço contém um domínio.
     * @param address o endereço a ser verificado.
     * @return verdadeiro se o endereço contém um domínio.
     */
    public static boolean containsDomain(String address) {
        if (address == null) {
            return false;
        } else {
            address = address.trim();
            if (SubnetIPv4.isValidIPv4(address)) {
                return false;
            } else {
                address = address.toLowerCase();
                return Pattern.matches(
                        "^([a-zA-Z0-9._%+=-]+@)?"
                        + "(_?(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\\.?)$", address
                        );

            }
        }
    }
    
    /**
     * Verifica se o endereço contém um domínio.
     * @param address o endereço a ser verificado.
     * @return verdadeiro se o endereço contém um domínio.
     */
    public static boolean isHostname(String address) {
        if (address == null) {
            return false;
        } else {
            address = address.trim();
            if (SubnetIPv4.isValidIPv4(address)) {
                return false;
            } else {
                address = address.toLowerCase();
                return Pattern.matches(
                        "^(_?(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\\.?)$", address
                        );

            }
        }
    }
    
    /**
     * Verifica se o endereço é um e-mail válido.
     * @param address o endereço a ser verificado.
     * @return verdadeiro se o endereço é um e-mail válido.
     */
    public static boolean isEmail(String address) {
        if (address == null) {
            return false;
        } else {
            address = address.trim();
            address = address.toLowerCase();
            return Pattern.matches(
                    "^[0-9a-zA-ZÀ-ÅÇ-ÏÑ-ÖÙ-Ýà-åç-ïñ-öù-ý._%/+=-]+@"
                    + "((?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\\.?)$", address
                    );
        }
    }
    
    /**
     * Verifica se o endereço é um TLD válido.
     * @param address o endereço a ser verificado.
     * @return verdadeiro se o endereço é um TLD válido.
     */
    public static boolean isTLD(String address) {
        address = address.trim();
        address = address.toLowerCase();
        return Pattern.matches(
                "^(\\.([a-z0-9]|[a-z0-9][a-z0-9-]+[a-z0-9])+)+$", address
                );
    }
    
    /**
     * Conjunto de todos os top domain level (TLD) conhecidos.
     */
    public static final HashSet<String> TLD_SET = new HashSet<String>();
    
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean TLD_CHANGED = false;

    /**
     * Intancia um novo registro de domínio.
     * @param result o resultado do WHOIS.
     * @throws QueryException se houver alguma falha da atualização do registro.
     */
    private Domain(String result) throws ProcessException {
        this.domain = refresh(result);
    }
    
    private boolean refresh() throws ProcessException {
        server = getWhoisServer(domain); // Temporário até final de transição.
        String result = Server.whois(domain, server);
        String domainResult = refresh(result);
        return domain.equals(domainResult);
    }
    
    public static synchronized TreeSet<String> getTLDSet() throws ProcessException {
        TreeSet<String> tldSet = new TreeSet<String>();
        tldSet.addAll(TLD_SET);
        return tldSet;
    }
    
    public static synchronized boolean addTLD(String tld) throws ProcessException {
        if (tld.charAt(0) != '.') {
            // Corrigir TLD sem ponto.
            tld = "." + tld;
        }
        if (Domain.isTLD(tld)) {
            tld = tld.toLowerCase();
            if (TLD_SET.add(tld)) {
                // Atualiza flag de atualização.
                TLD_CHANGED = true;
                return true;
            } else {
                return false;
            }
        } else {
            throw new ProcessException("ERROR: TLD INVALID");
        }
    }
    
    public static synchronized boolean removeTLD(String tld) throws ProcessException {
        if (tld.charAt(0) != '.') {
            // Corrigir TLD sem ponto.
            tld = "." + tld;
        }
        if (Domain.isTLD(tld)) {
            tld = tld.toLowerCase();
            if (TLD_SET.remove(tld)) {
                // Atualiza flag de atualização.
                TLD_CHANGED = true;
                return true;
            } else {
                return false;
            }
        } else {
            throw new ProcessException("ERROR: TLD INVALID");
        }
    }
    
    public static void main(String[] args) {
        try {
            String result = "\n% Copyright (c) Nic.br\n%  The use of the data below is only permitted as described in\n%  full by the terms of use at http://registro.br/termo/en.html ,\n%  being prohibited its distribution, commercialization or\n%  reproduction, in particular, to use it for advertising or\n%  any similar purpose.\n%  2015-09-29 14:23:51 (BRT -03:00)\n\n% Query rate limit exceeded. Reduced information.\n% Use https://registro.br/cgi-bin/nicbr/busca_dominio for domain availability.\n\ndomain:      mandatudo.net.br\nowner:       Vitor Gilmar Pereira\ncountry:     BR\nowner-c:     VIGPE13\nadmin-c:     VIGPE13\ntech-c:      VIGPE13\nbilling-c:   VIGPE13\nnserver:     ns12.cloudns.net  \nnsstat:      20150928 AA\nnslastaa:    20150928\nnserver:     pns11.cloudns.net  \nnsstat:      20150928 AA\nnslastaa:    20150928\nnserver:     pns15.cloudns.net  \nnsstat:      20150928 AA\nnslastaa:    20150928\nsaci:        yes\ncreated:     20150923 #14698273\nexpires:     20160923\nchanged:     20150923\nstatus:      published\n\nnic-hdl-br:  VIGPE13\nperson:      Vitor Gilmar Pereira\ncreated:     20130610\nchanged:     20140108\n\n% Security and mail abuse issues should also be addressed to\n% cert.br, http://www.cert.br/ , respectivelly to cert@cert.br\n% and mail-abuse@cert.br\n%\n% whois.registro.br accepts only direct match queries. Types\n% of queries are: domain (.br), registrant (tax ID), ticket,\n% provider, contact handle (ID), CIDR block, IP and ASN.\n\n";
            Domain domain = Domain.getDomain("mandatudo.net.br");
            for (int i = 0; i < 100; i++) {
                try {
                    System.out.println(domain.refresh(result));
                } catch (ProcessException ex) {
                    System.out.println(ex.getErrorMessage());
                }
            }
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
            System.exit(0);
        }
    }
    
    /**
     * Atualiza os campos do registro com resultado do WHOIS.
     * @param result o resultado do WHOIS.
     * @return o domínio real apresentado no resultado do WHOIS.
     * @throws QueryException se houver alguma falha da atualização do registro.
     */
    private String refresh(String result) throws ProcessException {
        try {
            String ownerNew = null;
            String owneridNew = null;
            String responsibleNew = null;
            String countryNew = null;
            String owner_cNew = null;
            String admin_cNew = null;
            String tech_cNew = null;
            String billing_cNew = null;
            Date createdNew = null;
            Date expiresNew = null;
            Date changedNew = null;
            String providerNew = null;
            String statusNew = null;
            String dsrecordNew = null;
            String dsstatusNew = null;
            String dslastokNew = null;
            String saciNew = null;
            String web_whoisNew = null;
            ArrayList<String> nameServerListNew = new ArrayList<String>();
            boolean reducedNew = false;
            String domainResult = null;
            BufferedReader reader = new BufferedReader(new StringReader(result));
            try {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.startsWith("domain:")) {
                        int index = line.indexOf(':') + 1;
                        domainResult = line.substring(index).trim();
                        // Descobre o TLD do domínio e adiciona no conjunto.
                        index = domainResult.indexOf('.');
                        String tld = domainResult.substring(index);
                        addTLD(tld);
                    } else if (line.startsWith("owner:")) {
                        int index = line.indexOf(':') + 1;
                        ownerNew = line.substring(index).trim();
                    } else if (line.startsWith("ownerid:")) {
                        int index = line.indexOf(':') + 1;
                        owneridNew = line.substring(index).trim();
                    } else if (line.startsWith("p.a. to:")) {
                        // Este cammpo "p.a. to" (power of attorney to) 
                        // é equivalente ao ownerid. A diferença é que 
                        // neste caso é o ownerid do procurador invés 
                        // do próprio dono extrangeiro representado.
                        // https://registro.br/dominio/reg-estrangeiros.html
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
                    } else if (line.startsWith("admin-c:")) {
                        int index = line.indexOf(':') + 1;
                        admin_cNew = line.substring(index).trim();
                    } else if (line.startsWith("tech-c:")) {
                        int index = line.indexOf(':') + 1;
                        tech_cNew = line.substring(index).trim();
                    } else if (line.startsWith("billing-c:")) {
                        int index = line.indexOf(':') + 1;
                        billing_cNew = line.substring(index).trim();
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
                        createdNew = DATE_FORMATTER.parse(valor);
                    } else if (line.startsWith("changed:")) {
                        int index = line.indexOf(':') + 1;
                        changedNew = DATE_FORMATTER.parse(line.substring(index).trim());
                    } else if (line.startsWith("expires:")) {
                        int index = line.indexOf(':') + 1;
                        expiresNew = DATE_FORMATTER.parse(line.substring(index).trim());
                    } else if (line.startsWith("status:")) {
                        int index = line.indexOf(':') + 1;
                        statusNew = line.substring(index).trim();
                    } else if (line.startsWith("dsrecord:")) {
                        int index = line.indexOf(':') + 1;
                        dsrecordNew = line.substring(index).trim();
                    } else if (line.startsWith("dsstatus:")) {
                        int index = line.indexOf(':') + 1;
                        dsstatusNew = line.substring(index).trim();
                    } else if (line.startsWith("dslastok:")) {
                        int index = line.indexOf(':') + 1;
                        dslastokNew = line.substring(index).trim();
                    } else if (line.startsWith("saci:")) {
                        int index = line.indexOf(':') + 1;
                        saciNew = line.substring(index).trim();
                    } else if (line.startsWith("web-whois:")) {
                        int index = line.indexOf(':') + 1;
                        web_whoisNew = line.substring(index).trim();
                    } else if (line.startsWith("provider:")) {
                        int index = line.indexOf(':') + 1;
                        providerNew = line.substring(index).trim();
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
                    } else if (line.startsWith("% No match for domain")) {
                        throw new ProcessException("ERROR: DOMAIN NOT FOUND");
                    } else if (line.startsWith("% release process: waiting")) {
                        throw new ProcessException("ERROR: WAITING");
                    } else if (line.startsWith("% reserved:    CG")) {
                        throw new ProcessException("ERROR: RESERVED");
                    } else if (line.startsWith("% Permission denied.")) {
                        throw new ProcessException("ERROR: WHOIS DENIED");
                    } else if (line.startsWith("% Permissão negada.")) {
                        throw new ProcessException("ERROR: WHOIS DENIED");
                    } else if (line.startsWith("% Maximum concurrent connections limit exceeded")) {
                        throw new ProcessException("ERROR: WHOIS CONCURRENT");
                    } else if (line.startsWith("% Query rate limit exceeded. Reduced information.")) {
                        // Informação reduzida devido ao estouro de limite de consultas.
                        Server.removeWhoisQuery();
                        reducedNew = true;
                    } else if (line.startsWith("% Query rate limit exceeded")) {
                        // Restrição total devido ao estouro de limite de consultas.
                        Server.removeWhoisQuery();
                        throw new ProcessException("ERROR: WHOIS QUERY LIMIT");
                    } else if (line.length() > 0 && Character.isLetter(line.charAt(0))) {
                        Server.logError("Linha não reconhecida: " + line);
                    }
                }
            } finally {
                reader.close();
            }
            if (domainResult == null) {
                throw new ProcessException("ERROR: DOMAIN NOT FOUND");
            } else {
                this.owner = ownerNew;
                if (owneridNew != null) {
                    // Associar ownerid somente se retornar valor.
                    this.ownerid = owneridNew;
                }
                this.responsible = responsibleNew;
                this.country = countryNew;
                this.owner_c = owner_cNew;
                this.admin_c = admin_cNew;
                this.tech_c = tech_cNew;
                this.billing_c = billing_cNew;
                this.created = createdNew;
                this.expires = expiresNew;
                this.changed = changedNew;
                this.provider = providerNew;
                this.status = statusNew;
                this.dsrecord = dsrecordNew;
                this.dsstatus = dsstatusNew;
                this.dslastok = dslastokNew;
                this.saci = saciNew;
                this.web_whois = web_whoisNew;
                this.nameServerList.clear();
                this.nameServerList.addAll(nameServerListNew);
                this.reduced = reducedNew;
                DOMAIN_CHANGED = true;
                this.lastRefresh = System.currentTimeMillis();
                this.queries = 1;
                // Retorna o domínio real indicado pelo WHOIS.
                return domainResult;
            }
        } catch (ProcessException ex) {
            throw ex;
        } catch (Exception ex) {
            Server.logError(ex);
            throw new ProcessException("ERROR: PARSING", ex);
        }
    }
    
    public Owner getOwner() throws ProcessException {
        return Owner.getOwner(ownerid);
    }
    
    public Handle getOwnerHandle() {
        return Handle.getHandle(owner_c);
    }
    
    public Handle getAdminHandle() {
        return Handle.getHandle(admin_c);
    }
    
    public Handle getTechHandle() {
        return Handle.getHandle(tech_c);
    }
    
    public Handle getBillingHandle() {
        return Handle.getHandle(billing_c);
    }
    
    /**
     * Retorna o valor de um campo do registro ou o valor de uma função.
     * @param key o campo do registro cujo valor deve ser retornado.
     * @return o valor de um campo do registro ou o valor de uma função.
     * @throws ProcessException se houver falha no processamento.
     */
    public String get(String key, boolean updated) throws ProcessException {
        if (key.equals("domain")) {
            return domain;
        } else if (key.equals("owner")) {
            return owner;
        } else if (key.equals("responsible")) {
            return responsible;
        } else if (key.equals("country")) {
            return country;
        } else if (key.equals("owner-c")) {
            return owner_c;
        } else if (key.equals("admin-c")) {
            return admin_c;
        } else if (key.equals("tech-c")) {
            return tech_c;
        } else if (key.equals("billing-c")) {
            return billing_c;
        } else if (key.equals("created")) {
            if (created == null) {
                return null;
            } else {
                return DATE_FORMATTER.format(created);
            }
        } else if (key.equals("expires")) {
            if (expires == null) {
                return null;
            } else {
                return DATE_FORMATTER.format(expires);
            }
        } else if (key.equals("changed")) {
            if (changed == null) {
                return null;
            } else {
                return DATE_FORMATTER.format(changed);
            }
        } else if (key.equals("provider")) {
            return provider;
        } else if (key.equals("status")) {
            return status;
        } else if (key.equals("dsrecord")) {
            return dsrecord;
        } else if (key.equals("dsstatus")) {
            return dsstatus;
        } else if (key.equals("dslastok")) {
            return dslastok;
        } else if (key.equals("saci")) {
            return saci;
        } else if (key.equals("web-whois")) {
            return web_whois;
        } else if (key.equals("nserver")) {
            return nameServerList.toString();
        } else if (key.equals("EXPIRATION")) {
            // Função que retorna o tempo em dias para expiração do domínio.
            if (expires == null) {
                return "NEVER";
            } else {
                long lifetime = (System.currentTimeMillis() - expires.getTime()) / 86400000;
                return Long.toString(lifetime);
            }
        } else if (key.equals("EXPIRED")) {
            // Função que retorna o se o domínio está expirado.
            if (expires == null) {
                return "false";
            } else if (created.after(expires)) {
                return "true";
            } else {
                return "false";
            }
        } else if (key.startsWith("owner/")) {
            int index = key.indexOf('/') + 1;
            key = key.substring(index);
            return getOwner().get(key, updated);
        } else if (key.startsWith("owner-c/")) {
            int index = key.indexOf('/') + 1;
            key = key.substring(index);
            return getOwnerHandle().get(key);
        } else if (key.startsWith("admin-c/")) {
            int index = key.indexOf('/') + 1;
            key = key.substring(index);
            return getAdminHandle().get(key);
        } else if (key.startsWith("tech-c/")) {
            int index = key.indexOf('/') + 1;
            key = key.substring(index);
            return getTechHandle().get(key);
        } else if (key.startsWith("billing-c/")) {
            int index = key.indexOf('/') + 1;
            key = key.substring(index);
            return getBillingHandle().get(key);
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
        } else if (reduced && updated) {
            // Ultima consulta reduzida.
            // Demais campos estão comprometidos.
            throw new ProcessException("ERROR: WHOIS QUERY LIMIT");
        } else if (key.equals("ownerid")) {
            return ownerid;
        } else {
            return null;
        }
    }
    
    public static String getValue(String address, String key) {
        if (address == null || key == null) {
            return null;
        } else if (Domain.containsDomain(address)) {
            try {
                Domain domain = Domain.getDomain(address);
                if (domain == null) {
                    return null;
                } else {
                    return domain.get(key, false);
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
                } else {
                    Server.logError(ex);
                    return null;
                }
            }
        } else {
            return null;
        }
    }
    
    public static Date getCreated(String address) {
        if (address == null) {
            return null;
        } else {
            try {
                Domain domain = Domain.getDomain(address);
                if (domain == null) {
                    return null;
                } else {
                    return domain.created;
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
                } else {
                    Server.logError(ex);
                    return null;
                }
            }
        }
    }
    
    public Date getCreated() {
        return created;
    }
    
    /**
     * Armazenamento de cache em disco.
     */
    public static void store() {
        storeDomain();
        storeTLD();
    }
    
    private static synchronized void storeDomain() {
        if (DOMAIN_CHANGED) {
            try {
                long time = System.currentTimeMillis();
                File file = new File("./data/domain.map");
                FileOutputStream outputStream = new FileOutputStream(file);
                try {
                    SerializationUtils.serialize(DOMAIN_MAP, outputStream);
                    // Atualiza flag de atualização.
                    DOMAIN_CHANGED = false;
                } finally {
                    outputStream.close();
                }
                Server.logStore(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static synchronized void storeTLD() {
        if (TLD_CHANGED) {
            try {
                long time = System.currentTimeMillis();
                File file = new File("./data/tld.set");
                FileOutputStream outputStream = new FileOutputStream(file);
                try {
                    SerializationUtils.serialize(TLD_SET, outputStream);
                    // Atualiza flag de atualização.
                    TLD_CHANGED = false;
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
        File file = new File("./data/domain.map");
        if (file.exists()) {
            try {
                HashMap<String, Domain> map;
                FileInputStream fileInputStream = new FileInputStream(file);
                try {
                    map = SerializationUtils.deserialize(fileInputStream);
                } finally {
                    fileInputStream.close();
                }
                DOMAIN_MAP.putAll(map);
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        time = System.currentTimeMillis();
        file = new File("./data/tld.set");
        if (file.exists()) {
            try {
                HashSet<String> set;
                FileInputStream fileInputStream = new FileInputStream(file);
                try {
                    set = SerializationUtils.deserialize(fileInputStream);
                } finally {
                    fileInputStream.close();
                }
                TLD_SET.addAll(set);
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    /**
     * Verifica a existência de registros DNS do host.
     * @param host o host que deve ser consultado.
     * @throws QueryException se o host não tiver 
     * registrado em DNS ou se houver falha de DNS.
     */
    private static void checkHost(String host) throws ProcessException {
        long time = System.currentTimeMillis();
        try {
            // Verifica se o domínio tem algum registro de diretório válido.
            Server.getAttributesDNS(host, null);
            Server.logCheckDNS(time, host, "EXIST");
        } catch (NameNotFoundException ex) {
            Server.logCheckDNS(time, host, "NXDOMAIN");
            throw new ProcessException("ERROR: DOMAIN NOT FOUND");
        } catch (ServiceUnavailableException ex) {
            Server.logCheckDNS(time, host, "UNAVAILABLE");
        } catch (CommunicationException ex) {
            Server.logCheckDNS(time, host, "TIMEOUT");
        } catch (Exception ex) {
            // Houve uma falha indefinida para encontrar os registros.
            Server.logError(ex);
        }
    }
    
    /**
     * Retorna o sevidor WHOIS para um determinado host.
     * @param host o host cujo servior WHOIS tem as informações do domínio.
     * @return o sevidor WHOIS para um determinado host.
     * @throws QueryException se nenhum servidor WHOIS for encontrado para o host.
     */
    private static String getWhoisServer(String host) throws ProcessException {
        if (host.endsWith(".br")) {
            return "whois.nic.br";
        } else {
            throw new ProcessException("ERROR: SERVER NOT FOUND");
        }
    }
    
    /**
     * Mapa de domínios com busca de hash O(1).
     */
    private static final HashMap<String,Domain> DOMAIN_MAP = new HashMap<String,Domain>();
    
    /**
     * Adciiona o registro de domínio no cache.
     * @param domain o domain que deve ser adicionado.
     */
    private static synchronized void addDomain(Domain domain) {
        DOMAIN_MAP.put(domain.getDomain(), domain);
        // Atualiza flag de atualização.
        DOMAIN_CHANGED = true;
    }
    
    /**
     * Remove o registro de domínio do cache.
     * @param domain o domain que deve ser removido.
     */
    private static synchronized void removeDomain(Domain domain) {
        if (DOMAIN_MAP.remove(domain.getDomain()) != null) {
            // Atualiza flag de atualização.
            DOMAIN_CHANGED = true;
        }
    }
    
    /**
     * Remove registro de domínio do cache.
     * @param host o host cujo registro de domínio deve ser removido.
     * @return o registro de domínio removido, se existir.
     * @throws ProcessException se houver falha no processamento.
     */
    public static synchronized Domain removeDomain(String host) throws ProcessException {
        String key = extractDomain(host, false);
        Domain domain = DOMAIN_MAP.remove(key);
        // Atualiza flag de atualização.
        DOMAIN_CHANGED = true;
        return domain;
    }
    
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean DOMAIN_CHANGED = false;
    
//    /**
//     * Conjunto de registros para atualização em background.
//     */
//    private static final TreeSet<Domain> DOMAIN_REFRESH = new TreeSet<Domain>();
    
    public static synchronized TreeSet<Domain> getDomainSet() {
        TreeSet<Domain> domainSet = new TreeSet<Domain>();
        domainSet.addAll(DOMAIN_MAP.values());
        return domainSet;
    }
    
    public static synchronized TreeSet<String> getDomainNameSet() {
        TreeSet<String> domainSet = new TreeSet<String>();
        domainSet.addAll(DOMAIN_MAP.keySet());
        return domainSet;
    }
    
    /**
     * Atualiza em background todos os registros adicionados no conjunto.
     */
    public static boolean backgroundRefresh() {
        Domain domainMax = null;
        for (Domain domain : getDomainSet()) {
            if (domain.isReduced() || domain.isRegistryExpired()) {
                if (domain.queries > 3) {
                    if (domainMax == null) {
                        domainMax = domain;
                    } else if (domainMax.queries < domain.queries) {
                        domainMax = domain;
                    } else if (domainMax.lastRefresh > domain.lastRefresh) {
                        domainMax = domain;
                    }
                }
            }
        }
        if (domainMax == null) {
            return false;
        } else {
            try {
                // Atualizando campos do registro.
                return domainMax.refresh();
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        }
    }
    
    /**
     * Atualiza o registro de domínio de um determinado host.
     * @param address o endereço cujo registro de domínio deve ser atualizado.
     * @throws ProcessException se houver falha no processamento.
     */
    public static void refreshDomain(String address) throws ProcessException {
        String key = extractDomain(address, false);
        // Busca eficiente O(1).
        if (DOMAIN_MAP.containsKey(key)) {
            // Domínio encontrado.
            Domain domain = DOMAIN_MAP.get(key);
            // Atualizando campos do registro.
            if (!domain.refresh()) {
                // Domínio real do resultado WHOIS não bate com o registro.
                // Pode haver a criação de uma nova TLD.
                // Apagando registro de domínio do cache.
                removeDomain(domain);
                // Segue para nova consulta.
            }
        } else {
            // Extrair o host se for e-mail.
            String host = extractHost(address, false);
            // Não encontrou o dominio em cache.
            // Selecionando servidor da pesquisa WHOIS.
            String server = getWhoisServer(host);
            // Verifica o DNS do host antes de fazer a consulta no WHOIS.
            // Evita consulta desnecessária no WHOIS.
            checkHost(host);
            // Domínio existente.
            // Realizando a consulta no WHOIS.
            String result = Server.whois(host, server);
            try {
                Domain domain = new Domain(result);
                domain.server = server; // Temporário até final de transição.
                // Adicinando registro em cache.
                addDomain(domain);
            } catch (ProcessException ex) {
                if (ex.getMessage().equals("ERROR: RESERVED")) {
                    // A chave de busca é um TLD.
                    if (TLD_SET.add(host)) {
                        // Atualiza flag de atualização.
                        TLD_CHANGED = true;
                    }
                }
                throw ex;
            }
        }
    }
    
    public static String getOwnerID(String address) {
        if (address.endsWith(".br")) {
            try {
                Domain domain = getDomain(address);
                return domain.get("ownerid", false);
            } catch (ProcessException ex) {
                if (ex.getMessage().equals("ERROR: NSLOOKUP")) {
                    return null;
                } else if (ex.getMessage().equals("ERROR: WHOIS QUERY LIMIT")) {
                    return null;
                } else if (ex.getMessage().equals("ERROR: DOMAIN NOT FOUND")) {
                    return null;
                } else if (ex.getMessage().equals("ERROR: WHOIS QUERY LIMIT")) {
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
    
    public static String getOwnerC(String address) {
        if (address.endsWith(".br")) {
            try {
                Domain domain = getDomain(address);
                return domain.get("owner-c", false);
            } catch (ProcessException ex) {
                if (ex.getMessage().equals("ERROR: NSLOOKUP")) {
                    return null;
                } else if (ex.getMessage().equals("ERROR: WHOIS QUERY LIMIT")) {
                    return null;
                } else if (ex.getMessage().equals("ERROR: DOMAIN NOT FOUND")) {
                    return null;
                } else if (ex.getMessage().equals("ERROR: WHOIS QUERY LIMIT")) {
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
    
    /**
     * Retorna o registro de domínio de um determinado host.
     * @param address o endereço cujo registro de domínio deve ser retornado.
     * @return o registro de domínio de um determinado endereço.
     * @throws ProcessException se houver falha no processamento.
     */
    public static Domain getDomain(String address) throws ProcessException {
        String key = extractDomain(address, false);
        // Busca eficiente O(1).
        if (DOMAIN_MAP.containsKey(key)) {
            // Domínio encontrado.
            Domain domain = DOMAIN_MAP.get(key);
            domain.queries++;
            if (domain.isRegistryExpired()) {
                // Registro desatualizado.
                // Atualizando campos do registro.
                if (domain.refresh()) {
                    // Domínio real do resultado WHOIS bate com o registro.
                    return domain;
                } else {
                    // Domínio real do resultado WHOIS não bate com o registro.
                    // Pode haver a criação de uma nova TLD.
                    // Apagando registro de domínio do cache.
                    removeDomain(domain);
                    // Segue para nova consulta.
                }
//            } else if (domain.isRegistryAlmostExpired() || domain.isReduced()) {
//                // Registro quase vencendo ou com informação reduzida.
//                // Adicionar no conjunto para atualização em background.
//                DOMAIN_REFRESH.add(domain);
//                return domain;
            } else {
                // Registro atualizado.
                return domain;
            }
        }
        // Extrair o host se for e-mail.
        String host = extractHost(address, false);
        // Não encontrou o dominio em cache.
        // Selecionando servidor da pesquisa WHOIS.
        String server = getWhoisServer(host);
        // Verifica o DNS do host antes de fazer a consulta no WHOIS.
        // Evita consulta desnecessária no WHOIS.
        checkHost(host);
        // Domínio existente.
        // Realizando a consulta no WHOIS.
        String result = Server.whois(host, server);
        try {
            Domain domain = new Domain(result);
            domain.server = server; // Temporário até final de transição.
            // Adicinando registro em cache.
            addDomain(domain);
            return domain;
        } catch (ProcessException ex) {
            if (ex.getMessage().equals("ERROR: RESERVED")) {
                // A chave de busca é um TLD.
                if (TLD_SET.add(host)) {
                    // Atualiza flag de atualização.
                    TLD_CHANGED = true;
                }
            }
            throw ex;
        }
    }
    
    /**
     * Retorna o domínio do registro.
     * @return o domínio do registro.
     */
    public String getDomain() {
        return domain;
    }
    
    @Override
    public int hashCode() {
        return domain.hashCode();
    }
    
    @Override
    public boolean equals(Object other) {
        if (other instanceof Domain) {
            return equals((Domain) other);
        } else {
            return false;
        }
    }
    
    /**
     * Verifica se o registro atual é o mesmo de outro.
     * @param other o outro registro a ser comparado.
     * @return verdadeiro se o registro passado é igual ao atual.
     */
    public boolean equals(Domain other) {
        if (other == null) {
            return false;
        } else {
            return this.domain.equals(other.domain);
        }
    }
    
    @Override
    public int compareTo(Domain other) {
        return this.domain.compareTo(other.domain);
    }
    
    @Override
    public String toString() {
        return domain;
    }
}
