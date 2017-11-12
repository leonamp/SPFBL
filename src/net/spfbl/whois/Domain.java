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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.Serializable;
import java.io.StringReader;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.StringTokenizer;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import javax.naming.CommunicationException;
import javax.naming.InvalidNameException;
import javax.naming.NameNotFoundException;
import javax.naming.OperationNotSupportedException;
import javax.naming.ServiceUnavailableException;
import net.spfbl.core.Core;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Representa o registro de domínio de um resultado WHOIS.
 * 
 * A chave primária dos registros é o atributo domainLocal.
 
 <h2>Mecanismo de busca</h2>
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

    private final String domain; // Domínio real indicado pelo WHOIS.
    private String owner; // Nome do dono do domínio.
    private String ownerid; // Identificação do dono do domínio.
    private String responsible; // Responsável pelo domínio.
    private String country; // País onde o domínio foi registrado.
    private String owner_c; // Código do dono do domínio.
    private String admin_c; // Código do administrador do domínio.
    private String tech_c; // Código do responsável técnico do domínio.
    private String billing_c; // Código do responsável pelos pagamentos do domínio.
    private Date created; // Data de criação do domínio pelo dono atual.
    private Date expires; // Data de expiração do registro do domínio.
    private Date changed; // Data da alteração do registro do domínio.
    private String provider; // Provedor de acesso do domínio.
    private String status; // Status atual do domínio.
    private String dsrecord;
    private String dsstatus;
    private String dslastok;
    private String saci;
    private String web_whois;
    
    /**
     * Lista dos servidores de nome do domínio.
     */
    private final ArrayList<String> nameServerList = new ArrayList<>();
    
    private String server = null; // Servidor onde a informação do domínio pode ser encontrada.
    private long lastRefresh = 0; // Última vez que houve atualização do registro em milisegundos.
    private boolean reduced = false; // Diz se a última consulta foi reduzida.
    private int queries = 1; // Contador de consultas.
    
    private static int REFRESH_TIME = 21;  // Prazo máximo que o registro deve permanecer em cache em dias.
    
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
        long expiredTime = (System.currentTimeMillis() - lastRefresh) / Server.DAY_TIME;
        if (isGraceTime()) {
            return expiredTime > 0;
        } else {
            return expiredTime > REFRESH_TIME;
        }
    }
    
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
            return Core.removerAcentuacao(address.substring(index)).toLowerCase();
        } else if (!Domain.isHostname(address)) {
            return null;
        } else if (pontuacao && !address.startsWith(".")) {
            return "." + Core.removerAcentuacao(address).toLowerCase();
        } else if (pontuacao && address.startsWith(".")) {
            return Core.removerAcentuacao(address).toLowerCase();
        } else if (!pontuacao && !address.startsWith(".")) {
            return Core.removerAcentuacao(address).toLowerCase();
        } else{
            return Core.removerAcentuacao(address.substring(1)).toLowerCase();
        }
    }
    
    public static boolean isOfficialTLD(String address) {
        if (address.contains("@")) {
            int index = address.lastIndexOf('@') + 1;
            address = '.' + address.substring(index);
            return TLD_SET.contains(address);
        } else {
            return TLD_SET.contains(address);
        }
    }
    
    public static boolean hasTLD(String address) {
        if ((address = extractHost(address, true)) == null) {
            return false;
        } else {
            int index = address.lastIndexOf('.');
            if (index == -1) {
                return false;
            } else {
                String tld = address.substring(index);
                return TLD_SET.contains(tld);
            }
        }
    }
    
    public static boolean isDomain(String address) {
        if ((address = extractHost(address, true)) == null) {
            return false;
        } else {
            int index = address.indexOf('.', 1);
            if (index == -1) {
                return !TLD_SET.contains(address);
            } else {
                String tld = address.substring(index);
                return TLD_SET.contains(tld);
            }
        }
    }
    
    public static String extractDomainSafe(String address, boolean pontuacao) {
        try {
            return extractDomain(address, pontuacao);
        } catch (ProcessException ex) {
            return null;
        }
    }
    
    /**
     * Extrai o domínio pelos TLDs conhecidos.
     * @param address o endereço que contém o domínio.
     * @param pontuacao se o ponto deve ser mantido na resposta.
     * @return o domínio pelos TLDs conhecidos.
     * @throws ProcessException se o endereço for um TLD.
     */
    public static String extractDomain(String address,
            boolean pontuacao) throws ProcessException {
        if ((address = extractHost(address, true)) == null) {
            return null;
        } else if (isOfficialTLD(address)) {
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
            beginIndex = address.lastIndexOf('.');
            int endIndex = address.length();
            if (pontuacao) {
                return "." + address.substring(beginIndex + 1, endIndex);
            } else {
                return address.substring(beginIndex + 1, endIndex);
            }
        }
    }
    
    /**
     * Extrai o TLD do endereço.
     * @param address o endereço que contém o TLD.
     * @param ponto se o ponto de ser mantido.
     * @return o TLDs do endereço.
     * @throws ProcessException se houve faha na extração do domínio.
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
        if (beginIndex == -1) {
            return (ponto ? "." : "") + address;
        } else if (beginIndex == 0) {
            return ponto ? address : address.substring(1);
        } else if (ponto) {
            return address.substring(beginIndex);
        } else {
            return address.substring(beginIndex+1);
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
                        + "(([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])"
                        + "(\\.([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9]))*)"
                        + "$", address
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
                        "^\\.?"
                        + "(([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])"
                        + "(\\.([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9]))*)"
                        + "\\.?$", address
                        );

            }
        }
    }
    
    /**
     * Extrai o host de um endereço de e-mail.
     * @param address o endereço que contém o host.
     * @param pontuacao se o arroba deve ser mantido na resposta.
     * @return o host do endereço de e-mail.
     */
    public static String normalizeHostname(String address, boolean pontuacao) {
        if (address == null) {
            return null;
        } else {
            address = address.replace(" ", "");
            if (address.endsWith(".")) {
                address = address.substring(0, address.length()-1);
            }
            if (address.length() == 0) {
                return null;
            } else if (address.contains("@")) {
                // O endereço é um e-mail.
                // Extrair a parte do host.
                int index = address.indexOf('@');
                if (!pontuacao) {
                    index++;
                }
                return Core.removerAcentuacao(address.substring(index)).toLowerCase();
            } else if (pontuacao && !address.startsWith(".")) {
                return "." + Core.removerAcentuacao(address).toLowerCase();
            } else if (pontuacao && address.startsWith(".")) {
                return Core.removerAcentuacao(address).toLowerCase();
            } else if (!pontuacao && !address.startsWith(".")) {
                return Core.removerAcentuacao(address).toLowerCase();
            } else{
                return Core.removerAcentuacao(address.substring(1)).toLowerCase();
            }
        }
    }
    
    /**
     * Verifica se o endereço é um e-mail válido.
     * @param address o endereço a ser verificado.
     * @return verdadeiro se o endereço é um e-mail válido.
     */
    public static boolean isMailFrom(String address) {
        if (address == null) {
            return false;
        } else if (address.length() > 256) {
            // RFC 5321: "The maximum total length of a 
            // reverse-path or forward-path is 256 characters"
            return false;
        } else {
            address = address.trim();
            address = address.toLowerCase();
            if (Pattern.matches(
                    "^"
                    + "[0-9a-zA-ZÀ-ÅÇ-ÏÑ-ÖÙ-Ýà-åç-ïñ-öù-ý._%/+=-]+"
                    + "@"
                    + "(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])"
                    + "(\\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9]))*)"
                    + "$", address
                    )) {
                int index = address.indexOf('@');
                String domain = address.substring(index+1);
                return Domain.isHostname(domain);
            } else {
                return false;
            }
        }
    }
    
    public static boolean isValidEmail(String address) {
        if (address == null) {
            return false;
        } else if (address.length() > 256) {
            // RFC 5321: "The maximum total length of a 
            // reverse-path or forward-path is 256 characters"
            return false;
        } else {
            address = address.trim();
            address = address.toLowerCase();
            if (Pattern.matches(
                    "^[0-9a-zA-Z._+-]+"
                    + "@"
                    + "(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])"
                    + "(\\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9]))*)"
                    + "$", address
                    )) {
                int index = address.indexOf('@');
                String domain = address.substring(index+1);
                return Domain.isHostname(domain);
            } else {
                return false;
            }
        }
    }
    
    /**
     * Verifica se o endereço é um TLD válido.
     * @param address o endereço a ser verificado.
     * @return verdadeiro se o endereço é um TLD válido.
     */
    public static boolean isValidTLD(String address) {
        address = address.trim();
        address = address.toLowerCase();
        return Pattern.matches(
                "^(\\.([a-z0-9]|[a-z0-9][a-z0-9-]+[a-z0-9])+)+$", address
                );
    }
    
    /**
     * Conjunto de todos os top domainLocal level (TLD) conhecidos.
     */
    public static final HashSet<String> TLD_SET = new HashSet<>();
    
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
        TreeSet<String> tldSet = new TreeSet<>();
        tldSet.addAll(TLD_SET);
        return tldSet;
    }
    
    public static synchronized boolean addTLD(String tld) throws ProcessException {
        if (tld.charAt(0) != '.') {
            tld = "." + tld;
        }
        if (Domain.isValidTLD(tld)) {
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
    
    public static synchronized boolean dropExactTLD(String tld) throws ProcessException {
        if (TLD_SET.remove(tld)) {
            // Atualiza flag de atualização.
            TLD_CHANGED = true;
            return true;
        } else {
            return false;
        }
    }
    
    public static TreeSet<String> dropAllTLD() throws ProcessException {
        TreeSet<String> tldSet = new TreeSet<String>();
        for (String tld : getTLDSet()) {
            if (dropExactTLD(tld)) {
                tldSet.add(tld);
            }
        }
        return tldSet;
    }
    
    public static boolean removeTLD(String tld) throws ProcessException {
        if (tld.charAt(0) != '.') {
            // Corrigir TLD sem ponto.
            tld = "." + tld;
        }
        if (Domain.isValidTLD(tld)) {
            tld = tld.toLowerCase();
            return dropExactTLD(tld);
        } else {
            throw new ProcessException("ERROR: TLD INVALID");
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
            ArrayList<String> nameServerListNew = new ArrayList<>();
            boolean reducedNew = false;
            String domainResult = null;
            SimpleDateFormat dateFormatter = new SimpleDateFormat("yyyyMMdd");
            try (BufferedReader reader = new BufferedReader(new StringReader(result))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    try {
                        line = line.trim();
                        if (line.startsWith("domain:")) {
                            int index = line.indexOf(':') + 1;
                            domainResult = line.substring(index).trim();
                            // Remove a versão de domínios com acentuação.
                            index = domainResult.lastIndexOf(' ') + 1;
                            domainResult = domainResult.substring(index);
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
                            if (valor.equals("multiple points")) {
                                valor = null;
                            } else if (valor.startsWith("before ")) {
                                index = line.indexOf(' ') - 1;
                                valor = valor.substring(index).trim();
                            }
                            if (valor != null && valor.length() > 7) {
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
                        } else if (line.startsWith("expires:")) {
                            int index = line.indexOf(':') + 1;
                            String valor = line.substring(index).trim();
                            if (valor.length() > 7) {
                                valor = valor.substring(0, 8);
                                expiresNew = dateFormatter.parse(valor);
                            }
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
                                handle.setProvider(provider2);
                                handle.setCountry(country2);
                                handle.setChanged(changed2);
                            } catch (Exception ex) {
                                Server.logError(line);
                                Server.logError(ex);
                            }
                        } else if (line.startsWith("ticket:")) {
                            // Do nothing.
                        } else if (line.startsWith("nsstat:")) {
                            // Do nothing.
                        } else if (line.startsWith("% No match for domain")) {
                            throw new ProcessException("ERROR: DOMAIN NOT FOUND");
                        } else if (line.startsWith("% release process: ")) {
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
                            Server.removeWhoisQueryHour();
                            reducedNew = true;
                        } else if (line.startsWith("% Query rate limit exceeded")) {
                            // Restrição total devido ao estouro de limite de consultas.
                            Server.removeWhoisQueryDay();
                            throw new ProcessException("ERROR: WHOIS QUERY LIMIT");
                        } else if (line.length() > 0 && Character.isLetter(line.charAt(0))) {
                            Server.logError("Linha não reconhecida: " + line);
                        }
                    } catch (NumberFormatException ex) {
                        Server.logError(ex);
                        Server.logError(line);
                    }
                }
            }
            if (domainResult == null) {
                throw new ProcessException("ERROR: DOMAIN NOT FOUND");
            } else {
                this.owner = ownerNew;
                if (owneridNew != null) {
                    // Associar ownerid somente se retornar valor.
                    this.ownerid = Owner.normalizeID(owneridNew);
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
            throw new ProcessException("ERROR: PARSING " + result, ex);
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
    
    public static boolean isGraceTime(String address) {
        try {
            if (address == null) {
                return false;
            } else if (address.endsWith(".br")) {
                Domain domain = Domain.getDomain(address);
                if (domain == null) {
                    return false;
                } else {
                    return domain.isGraceTime();
                }
            } else {
                return false;
            }
        } catch (ProcessException ex) {
            if (ex.isErrorMessage("WAITING")) {
                return true;
            } else if (ex.isErrorMessage("DOMAIN NOT FOUND")) {
                return false;
            } else if (ex.isErrorMessage("TOO MANY CONNECTIONS")) {
                return false;
            } else if (ex.isErrorMessage("WHOIS QUERY LIMIT")) {
                return false;
            } else {
                Server.logError(ex);
                return false;
            }
        }
    }
    
    public int getLifeTime() {
        if (created == null) {
            return 0;
        } else {
            return (int) ((System.currentTimeMillis() - created.getTime()) / 86400000);
        }
    }
    
    public boolean isGraceTime() {
        if (expires == null && getLifeTime() < 7) {
            String domainLocal = getDomain();
            int beginIndex = domainLocal.indexOf('.', 1);
            int endIndex = domainLocal.length();
            String tld = domainLocal.substring(beginIndex, endIndex);
            if (tld.equals(".br")) {
                return false;
            } else if (tld.equals(".edu.br")) {
                return false;
            } else if (tld.equals(".mil.br")) {
                return false;
            } else if (tld.equals(".gov.br")) {
                return false;
            } else if (tld.equals(".leg.br")) {
                return false;
            } else if (tld.equals(".def.br")) {
                return false;
            } else if (tld.equals(".jus.br")) {
                return false;
            } else if (tld.equals(".mp.br")) {
                return false;
            } else {
                return tld.endsWith(".br");
            }
        } else {
            return false;
        }
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
                return new SimpleDateFormat("yyyyMMdd").format(created);
            }
        } else if (key.equals("expires")) {
            if (expires == null) {
                return null;
            } else {
                return new SimpleDateFormat("yyyyMMdd").format(expires);
            }
        } else if (key.equals("changed")) {
            if (changed == null) {
                return null;
            } else {
                return new SimpleDateFormat("yyyyMMdd").format(changed);
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
            Owner ownerLocal = getOwner();
            if (ownerLocal == null) {
                return null;
            } else {
                return ownerLocal.get(key, updated);
            }
        } else if (key.startsWith("owner-c/")) {
            int index = key.indexOf('/') + 1;
            key = key.substring(index);
            Handle ownerLocal = getOwnerHandle();
            if (ownerLocal == null) {
                return null;
            } else {
                return ownerLocal.get(key);
            }
        } else if (key.startsWith("admin-c/")) {
            int index = key.indexOf('/') + 1;
            key = key.substring(index);
            Handle admin = getAdminHandle();
            if (admin == null) {
                return null;
            } else {
                return admin.get(key);
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
        } else if (key.startsWith("billing-c/")) {
            int index = key.indexOf('/') + 1;
            key = key.substring(index);
            Handle billing = getBillingHandle();
            if (billing == null) {
                return null;
            } else {
                return billing.get(key);
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
        } else if (reduced && updated) {
            // Ultima consulta reduzida.
            // Demais campos estão comprometidos.
            throw new ProcessException("ERROR: WHOIS QUERY LIMIT");
        } else if (key.equals("ownerid")) {
            return Owner.normalizeID(ownerid);
        } else {
            return null;
        }
    }
    
    public static String getValue(String address, String key) {
        if (address == null || key == null) {
            return null;
        } else {
            try {
                Domain domain = Domain.getDomain(address);
                if (domain == null) {
                    return null;
                } else {
                    return domain.get(key, false);
                }
            } catch (ProcessException ex) {
                if (ex.isErrorMessage("NSLOOKUP")) {
                    return null;
                } else if (ex.isErrorMessage("WAITING")) {
                    return null;
                } else if (ex.isErrorMessage("DOMAIN NOT FOUND")) {
                    return null;
                } else if (ex.isErrorMessage("RESERVED")) {
                    return null;
                } else if (ex.isErrorMessage("WHOIS CONNECTION FAIL")) {
                    return null;
                } else if (ex.isErrorMessage("WHOIS QUERY LIMIT")) {
                    return null;
                } else if (ex.isErrorMessage("TOO MANY CONNECTIONS")) {
                    return null;
                } else {
                    Server.logError(ex);
                    return null;
                }
            }
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
    
    private static synchronized HashMap<String,Domain> getDomainMap() {
        HashMap<String,Domain> map = new HashMap<>();
        map.putAll(MAP);
        return map;
    }
    
    private static void storeDomain() {
        if (DOMAIN_CHANGED) {
            try {
                long time = System.currentTimeMillis();
                File file = new File("./data/domain.map");
                HashMap<String,Domain> map = getDomainMap();
                try (FileOutputStream outputStream = new FileOutputStream(file)) {
                    SerializationUtils.serialize(map, outputStream);
                    // Atualiza flag de atualização.
                    DOMAIN_CHANGED = false;
                }
                Server.logStore(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static synchronized TreeSet<String> getSetTLD() {
        TreeSet<String> set = new TreeSet<>();
        set.addAll(TLD_SET);
        return set;
    }
    
    private static void storeTLD() {
        if (TLD_CHANGED) {
            try {
                long time = System.currentTimeMillis();
                File file = new File("./data/tld.set");
                TreeSet<String> set = getSetTLD();
                try (FileOutputStream outputStream = new FileOutputStream(file)) {
                    SerializationUtils.serialize(set, outputStream);
                    // Atualiza flag de atualização.
                    TLD_CHANGED = false;
                }
                Server.logStore(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static synchronized Domain put(String key, Domain domain) {
        return MAP.put(key, domain);
    }
    
    private static synchronized void addAll(Collection<String> set) {
        for (String tld : set) {
            if (!tld.startsWith(".")) {
                tld = '.' + tld;
            }
            TLD_SET.add(tld);
        }
    }
    
    /**
     * Carregamento de cache do disco.
     */
    public static void load() {
        long time = System.currentTimeMillis();
        File file = new File("./data/domain.map");
        if (file.exists()) {
            try {
                HashMap<String,Object> map;
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    map = SerializationUtils.deserialize(fileInputStream);
                }
                for (String key : map.keySet()) {
                    Object value = map.get(key);
                    if (value instanceof Domain) {
                        Domain domain = (Domain) value;
                        put(key, domain);
                    }
                }
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        time = System.currentTimeMillis();
        file = new File("./data/tld.set");
        if (file.exists()) {
            try {
                Collection<String> set;
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    set = SerializationUtils.deserialize(fileInputStream);
                }
                addAll(set);
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
        } catch (NameNotFoundException ex) {
            throw new ProcessException("ERROR: DOMAIN NOT FOUND");
        } catch (CommunicationException ex) {
            Server.logCheckDNS(time, host, "TIMEOUT");
        } catch (ServiceUnavailableException ex) {
            Server.logCheckDNS(time, host, "SERVFAIL");
        } catch (InvalidNameException ex) {
            Server.logCheckDNS(time, host, "INVALID");
        } catch (OperationNotSupportedException ex) {
            Server.logCheckDNS(time, host, "REFUSED");
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
    private static final HashMap<String,Domain> MAP = new HashMap<>();
    
    public synchronized boolean drop() {
        if (MAP.remove(getDomain()) != null) {
            DOMAIN_CHANGED = true;
            return true;
        } else {
            return false;
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
        Domain domain = MAP.remove(key);
        // Atualiza flag de atualização.
        DOMAIN_CHANGED = true;
        return domain;
    }
    
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean DOMAIN_CHANGED = false;
    
    public static synchronized TreeSet<Domain> getDomainSet() {
        TreeSet<Domain> domainSet = new TreeSet<>();
        domainSet.addAll(MAP.values());
        return domainSet;
    }
    
    public static synchronized TreeSet<String> getDomainNameSet() {
        TreeSet<String> domainSet = new TreeSet<>();
        domainSet.addAll(MAP.keySet());
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
            } catch (ProcessException ex) {
                if (ex.isErrorMessage("WAITING")) {
                    domainMax.drop();
                } else if (ex.isErrorMessage("DOMAIN NOT FOUND")) {
                    domainMax.drop();
                } else if (ex.isErrorMessage("WHOIS QUERY LIMIT")) {
                    // Fazer nada.
                } else if (ex.isErrorMessage("WHOIS CONNECTION FAIL")) {
                    // Fazer nada.
                } else if (ex.isErrorMessage("TOO MANY CONNECTIONS")) {
                    // Fazer nada.
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
     * Atualiza o registro de domínio de um determinado host.
     * @param address o endereço cujo registro de domínio deve ser atualizado.
     * @throws ProcessException se houver falha no processamento.
     */
    public static synchronized void refreshDomain(String address) throws ProcessException {
        String key = extractDomain(address, false);
        // Busca eficiente O(1).
        if (MAP.containsKey(key)) {
            // Domínio encontrado.
            Domain domain = MAP.get(key);
            // Atualizando campos do registro.
            if (!domain.refresh()) {
                // Domínio real do resultado WHOIS não bate com o registro.
                // Pode haver a criação de uma nova TLD.
                // Apagando registro de domínio do cache.
                if (MAP.remove(domain.getDomain()) != null) {
                    // Atualiza flag de atualização.
                    DOMAIN_CHANGED = true;
                }
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
                MAP.put(domain.getDomain(), domain);
                DOMAIN_CHANGED = true;
            } catch (ProcessException ex) {
                if (ex.isErrorMessage("RESERVED")) {
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
        if (address == null) {
            return null;
        } else if (address.endsWith(".br")) {
            try {
                Domain domain = getDomain(address);
                if (domain == null) {
                    return null;
                } else {
                    return domain.get("ownerid", false);
                }
            } catch (ProcessException ex) {
                if (ex.isErrorMessage("NSLOOKUP")) {
                    return null;
                } else if (ex.isErrorMessage("WHOIS QUERY LIMIT")) {
                    return null;
                } else if (ex.isErrorMessage("DOMAIN NOT FOUND")) {
                    return null;
                } else if (ex.isErrorMessage("WHOIS QUERY LIMIT")) {
                    return null;
                } else if (ex.isErrorMessage("WHOIS QUERY LIMIT")) {
                    return null;
                } else if (ex.isErrorMessage("TOO MANY CONNECTIONS")) {
                    return null;
                } else if (ex.isErrorMessage("WHOIS CONNECTION FAIL")) {
                    return null;
                } else if (ex.isErrorMessage("RESERVED")) {
                    return null;
                } else if (ex.isErrorMessage("WAITING")) {
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
                if (domain == null) {
                    return null;
                } else {
                    return domain.get("owner-c", false);
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
    
    public static String revert(String hostname) {
        if (hostname == null) {
            return null;
        } else {
            StringTokenizer tokenizer = new StringTokenizer(hostname, ".");
            String result = tokenizer.nextToken();
            while (tokenizer.hasMoreTokens()) {
                result = tokenizer.nextToken() + '.' + result;
            }
            return '.' + result;
        }
    }
    
    private static synchronized Domain newDomain(String host) throws ProcessException {
        // Selecionando servidor da pesquisa WHOIS.
        String server = getWhoisServer(host);
        // Domínio existente.
        // Realizando a consulta no WHOIS.
        String result = Server.whois(host, server);
        try {
            Domain domain = new Domain(result);
            domain.server = server; // Temporário até final de transição.
            // Adicinando registro em cache.
            MAP.put(domain.getDomain(), domain);
            DOMAIN_CHANGED = true;
            return domain;
        } catch (ProcessException ex) {
            if (ex.isErrorMessage("RESERVED")) {
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
     * Retorna o registro de domínio de um determinado host.
     * @param address o endereço cujo registro de domínio deve ser retornado.
     * @return o registro de domínio de um determinado endereço.
     * @throws ProcessException se houver falha no processamento.
     */
    public static Domain getDomain(String address) throws ProcessException {
        String key = extractDomain(address, false);
        Domain domain = MAP.get(key);
        // Busca eficiente O(1).
        if (domain != null) {
            // Domínio encontrado.
            domain.queries++;
            if (domain.isRegistryExpired()) {
                // Registro desatualizado.
                // Atualizando campos do registro.
                if (domain.refresh()) {
                    // Domínio real do resultado WHOIS bate com o registro.
                    return domain;
                } else if (MAP.remove(domain.getDomain()) != null) {
                    // Domínio real do resultado WHOIS não bate com o registro.
                    // Pode haver a criação de uma nova TLD.
                    // Apagando registro de domínio do cache.
                    DOMAIN_CHANGED = true;
                    // Segue para nova consulta.
                }
            } else {
                // Registro atualizado.
                return domain;
            }
        }
        // Extrair o host se for e-mail.
        String host = extractHost(address, false);
        // Verifica o DNS do host antes de fazer a consulta no WHOIS.
        // Evita consulta desnecessária no WHOIS.
        checkHost(host);
        return newDomain(host);
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
