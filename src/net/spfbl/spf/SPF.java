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
package net.spfbl.spf;

import net.spfbl.core.Core;
import net.spfbl.core.NormalDistribution;
import net.spfbl.whois.Domain;
import net.spfbl.core.ProcessException;
import net.spfbl.core.Server;
import net.spfbl.whois.Owner;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv4;
import net.spfbl.whois.SubnetIPv6;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.Serializable;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.naming.CommunicationException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.InvalidAttributeIdentifierException;
import net.spfbl.core.Peer;
import net.spfbl.core.Peer.Binomial;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Representa o registro SPF de um deterninado hostname.
 *
 * Implementação da RFC 7208, com algumas modificações para atender condições
 * específicas.
 *
 * Quando a consulta é feita, o resultado do SPF é considerado para determinar o
 * responsável pela mensagem. Uma vez encontrado o responsável, um ticket SPFBL
 * é gerado através de criptografia na base 64. Este ticket é enviado juntamente
 * o qualificador SPF da consulta. O cliente da consulta deve extrair o ticket
 * do resultado e adicionar no cabeçalho da mensagem utilizando o campo
 * "Received-SPFBL".
 *
 * A regra de determinação de responsabilidade é usada para gerar o ticket SPFBL
 * e funciona da seguinte forma: 1. Se retornar PASS, o remetente é o
 * responsável pela mensagem ou 2. Caso contrário, o hostname é responsável pela
 * mensagem.
 *
 * No primeiro caso, onde o remetente é responsável pela mensagem, o ticket é
 * gerado com a seguinte regra: 1. Se o domínio do rementente estiver na lista
 * de provedores, então o endereço de e-mail completo é utilizado ou 2. Caso
 * contrário, o hostname e domínio do rementente são utilizados.
 *
 * No segundo caso, onde o hostname é responsável pela mensagem, o ticket é
 * gerado com a seguinte regra: 1. Se o HELO apontar para o IP, então o próprio
 * HELO e o domínio do HELO são utilizados ou 2. Caso contrário, o IP é
 * utilizado.
 *
 * Todas as consultas são registradas numa distribuição de probabilidade, onde é
 * possível alternar de HAM para SPAM utilizando o ticket gerado. Uma vez
 * recebida a reclamação com o ticket, o serviço descriptografa o ticket e
 * extrai os responsaveis pelo envio.
 *
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public final class SPF implements Serializable {

    private static final long serialVersionUID = 1L;
    private final String hostname;
    private String redirect = null;
    private String explanation = null;
    private ArrayList<Mechanism> mechanismList = null;
    private Qualifier all = null; // Qualificador do mecanismo all.
    private boolean error = false; // Se houve erro de sintaxe.
    private int queries = 0; // Contador de consultas.
    private int nxdomain = 0; // Contador de inexistência de domínio.
    private long lastRefresh = 0; // Última vez que houve atualização do registro em milisegundos.
    private static final int REFRESH_TIME = 7; // Prazo máximo que o registro deve permanecer em cache em dias.
    
    private SPF(String hostname) throws ProcessException {
        this.hostname = hostname;
        // Sempre usar best-guess em caso de 
        // indisponibilidade de DNS na primeira consulta.
        refresh(false, true);
    }

    /**
     * Consulta o registro SPF nos registros DNS do domínio. Se houver mais de
     * dois registros diferentes, realiza o merge do forma a retornar um único
     * registro.
     *
     * @param hostname o nome do hostname para consulta do SPF.
     * @param bgWhenUnavailable usar best-guess quando houver erro temporário
     * para alcançar o registro.
     * @return o registro SPF consertado, padronuzado e mergeado.
     * @throws ProcessException
     */
    private static LinkedList<String> getRegistrySPF(String hostname,
            boolean bgWhenUnavailable) throws ProcessException {
        LinkedList<String> registryList = new LinkedList<String>();
        try {
//            if (CacheGuess.contains(hostname)) {
//                // Sempre que houver registro de
//                // chute, sobrepor registro atual.
//                registryList.add(CacheGuess.get(hostname));
//            } else {
//                // Caso contrário procurar nos
//                // registros oficiais do domínio.
                try {
                    Attributes attributes = Server.getAttributesDNS(
                            hostname, new String[]{"SPF"});
                    Attribute attribute = attributes.get("SPF");
                    if (attribute != null) {
                        for (int index = 0; index < attribute.size(); index++) {
                            String registry = (String) attribute.get(index);
                            if (registry.contains("v=spf1 ")) {
                                registry = fixRegistry(registry);
                                if (!registryList.contains(registry)) {
                                    registryList.add(registry);
                                }
                            }
                        }
                    }
                } catch (InvalidAttributeIdentifierException ex) {
                    // Não encontrou registro SPF.
                }
                if (registryList.isEmpty()) {
                    try {
                        Attributes attributes = Server.getAttributesDNS(
                                hostname, new String[]{"TXT"});
                        Attribute attribute = attributes.get("TXT");
                        if (attribute != null) {
                            for (int index = 0; index < attribute.size(); index++) {
                                String registry = (String) attribute.get(index);
                                if (registry.contains("v=spf1 ")) {
                                    registry = fixRegistry(registry);
                                    if (!registryList.contains(registry)) {
                                        registryList.add(registry);
                                    }
                                }
                            }

                        }
                    } catch (InvalidAttributeIdentifierException ex2) {
                        // Não encontrou registro TXT.
                    }
                }
//            }
            if (registryList.isEmpty()) {
//                hostname = "." + hostname;
//                if (CacheGuess.contains(hostname)) {
//                    // Significa que um palpite SPF
//                    // foi registrado para este hostname.
//                    // Neste caso utilizar o paltpite específico.
//                    registryList.add(CacheGuess.get(hostname));
//                } else {
//                    // Se não hoouver palpite específico para o hostname,
//                    // utilizar o palpite padrão, porém adaptado para IPv6.
//                    // http://www.openspf.org/FAQ/Best_guess_record
//                    registryList.add(CacheGuess.BEST_GUESS);
//                }
                
                // Como o domínio não tem registro SPF,
                // utilizar um registro SPF de chute do sistema.
                String guess = CacheGuess.get(hostname);
                registryList.add(guess);
            }
            return registryList;
        } catch (NameNotFoundException ex) {
            return null;
        } catch (NamingException ex) {
            if (bgWhenUnavailable) {
                // Na indisponibilidade do DNS
                // utilizar um registro SPF de chute do sistema.
                String guess = CacheGuess.get(hostname);
                registryList.add(guess);
                return registryList;
            } else if (ex instanceof CommunicationException) {
                throw new ProcessException("ERROR: DNS UNAVAILABLE");
            } else {
                throw new ProcessException("ERROR: DNS UNAVAILABLE", ex);
            }
        } catch (Exception ex) {
            throw new ProcessException("ERROR: FATAL", ex);
        }
    }

    /**
     * Algoritmo para consertar e padronizar o registro SPF.
     *
     * @param registry o registro SPF original.
     * @return o registro SPF consertado e padronizado.
     */
    private static String fixRegistry(String registry) {
        String vesion = "v=spf1";
        String all = null;
        String redirect = null;
        String explanation = null;
        LinkedList<String> midleList = new LinkedList<String>();
        LinkedList<String> errorList = new LinkedList<String>();
        registry = registry.replace("\\\"", "\"");
        registry = registry.replace("\" \"", "");
        registry = registry.replace("\"", "");
        registry = registry.toLowerCase();
        StringTokenizer tokenizer = new StringTokenizer(registry, " ");
        while (tokenizer.hasMoreTokens()) {
            Boolean valid;
            String token = tokenizer.nextToken();
            if (token.equals("v=spf1")) {
                vesion = token;
                valid = null;
            } else if (token.startsWith("redirect=")) {
                redirect = token;
                valid = null;
            } else if (token.startsWith("exp=")) {
                explanation = token;
                valid = null;
            } else if (token.equals("v=msv1")) {
                valid = true;
            } else if (token.startsWith("t=") && token.length() == 32) {
                valid = true;
            } else if (isMechanismMiddle(token)) {
                valid = true;
            } else if (isMechanismAll(token)) {
                all = token;
                valid = null;
            } else {
                valid = false;
            }
            if (valid == null) {
                mergeMechanism(midleList, errorList);
            } else if (valid == true) {
                mergeMechanism(midleList, errorList);
                if (!midleList.contains(token)) { // Não considera tokens repetidos.
                    midleList.add(token);
                }
            } else if (valid == false) {
                errorList.add(token);
            }
        }
        registry = vesion;
        if (redirect == null) {
            for (String token : midleList) {
                registry += ' ' + token;
            }
            if (all != null) {
                registry += ' ' + all;
            }
        } else {
            registry += ' ' + redirect;
        }
        if (explanation != null) {
            registry += ' ' + explanation;
        }
        return registry;
    }

    /**
     * Merge nas listas de fixação de SPF.
     *
     * @param midleList lista dos mecanismos centrais.
     * @param errorList lista dos mecanismos com erro de sintaxe.
     */
    private static void mergeMechanism(
            LinkedList<String> midleList,
            LinkedList<String> errorList) {
        while (!errorList.isEmpty()) {
            boolean fixed = false;
            if (errorList.size() > 1) {
                for (int index = 1; index < errorList.size(); index++) {
                    String tokenFix = errorList.getFirst();
                    for (String tokenError : errorList.subList(1, index + 1)) {
                        tokenFix += tokenError;
                    }
                    if (isMechanismMiddle(tokenFix)) {
                        midleList.add(tokenFix);
                        int k = 0;
                        while (k++ <= index) {
                            errorList.removeFirst();
                        }
                        fixed = true;
                        break;
                    }
                }

            }
            if (!fixed) {
                // Não foi capaz de corrigir o erro.
                midleList.add(errorList.removeFirst());
            }
        }
    }

    /**
     * Verifica se o whois é um mecanismo cental.
     *
     * @param token o whois do registro SPF.
     * @return verdadeiro se o whois é um mecanismo cental.
     */
    private static boolean isMechanismMiddle(String token) {
        if (isMechanismIPv4(token)) {
            return true;
        } else if (isMechanismIPv6(token)) {
            return true;
        } else if (isMechanismA(token)) {
            return true;
        } else if (isMechanismMX(token)) {
            return true;
        } else if (isMechanismPTR(token)) {
            return true;
        } else if (isMechanismExistis(token)) {
            return true;
        } else if (isMechanismInclude(token)) {
            return true;
        } else {
            return false;
        }
    }
    
    private boolean isInexistent() {
        return nxdomain > 0;
    }

    private boolean isDefinitelyInexistent() {
        // Se consultou mais de 32 vezes 
        // seguidas com 3 retornos de inexistência,
        // considerar como definitivamente inexistente.
        return nxdomain > 3 && queries > 32;
    }

    /**
     * Método seguro para incrementar nxdomain sem deixar que ele se torne
     * negativo.
     */
    private void addInexistent() {
        if (nxdomain < Integer.MAX_VALUE) {
            nxdomain++;
        }
    }
    
    private synchronized void updateLastRefresh() {
        this.lastRefresh = System.currentTimeMillis();
    }

    /**
     * Atualiza o registro SPF de um hostname.
     *
     * @throws ProcessException se houver falha no processamento.
     */
    private synchronized void refresh(boolean load,
            boolean bgWhenUnavailable) throws ProcessException {
        long time = System.currentTimeMillis();
        LinkedList<String> registryList = getRegistrySPF(
                hostname, bgWhenUnavailable);
        if (registryList == null) {
            // Domínimo não encontrado.
            this.mechanismList = null;
            this.all = null;
            this.redirect = null;
            this.explanation = null;
            this.error = false;
            CacheSPF.CHANGED = true;
            this.addInexistent();
            updateLastRefresh();
            Server.logLookupSPF(time, hostname, "NXDOMAIN");
        } else if (registryList.isEmpty()) {
            // Sem registro SPF.
            this.mechanismList = new ArrayList<Mechanism>();
            this.all = null;
            this.redirect = null;
            this.explanation = null;
            this.error = false;
            CacheSPF.CHANGED = true;
            this.queries = 0;
            this.nxdomain = 0;
            updateLastRefresh();
            Server.logLookupSPF(time, hostname, "NO REGISTRY");
        } else {
            ArrayList<Mechanism> mechanismListIP = new ArrayList<Mechanism>();
            ArrayList<Mechanism> mechanismListDNS = new ArrayList<Mechanism>();
            ArrayList<Mechanism> mechanismListInclude = new ArrayList<Mechanism>();
            ArrayList<Mechanism> mechanismListPTR = new ArrayList<Mechanism>();
            TreeSet<String> visitedTokens = new TreeSet<String>();
            Qualifier allLocal = null;
            String redirectLocal = null;
            String explanationLocal = null;
            boolean errorQuery = false;
            String fixed;
            String result = null;
            for (String registry : registryList) {
                boolean errorRegistry = false;
                StringTokenizer tokenizer = new StringTokenizer(registry, " ");
                while (tokenizer.hasMoreTokens()) {
                    String token = tokenizer.nextToken();
                    if (visitedTokens.contains(token)) {
                        // Token já visitado.
                    } else if (token.equals("spf1")) {
                        // Nada deve ser feito.
                    } else if (token.equals("v=spf1")) {
                        // Nada deve ser feito.
                    } else if (token.equals("v=msv1")) {
                        // Nada deve ser feito.
                    } else if (token.equals("+")) {
                        // Ignorar qualificadores isolados.
                    } else if (token.startsWith("t=") && token.length() == 32) {
                        // Nada deve ser feito.
                    } else if (isMechanismAll(token)) {
                        // Não permitir qualificadores permissivos para all.
                        switch (token.charAt(0)) {
                            case '-':
                                allLocal = Qualifier.FAIL;
                                break;
                            case '~':
                                allLocal = Qualifier.SOFTFAIL;
                                break;
                            default:
                                allLocal = Qualifier.NEUTRAL; // Default qualifier or all.
                        }
                    } else if (isMechanismIPv4(token)) {
                        mechanismListIP.add(new MechanismIPv4(token));
                    } else if (isMechanismIPv6(token)) {
                        mechanismListIP.add(new MechanismIPv6(token));
                    } else if (isMechanismA(token)) {
                        mechanismListDNS.add(new MechanismA(token, load));
                    } else if (isMechanismMX(token)) {
                        mechanismListDNS.add(new MechanismMX(token, load));
                    } else if (isMechanismPTR(token)) {
                        mechanismListPTR.add(new MechanismPTR(token));
                    } else if (isMechanismExistis(token)) {
                        mechanismListDNS.add(new MechanismExists(token));
                    } else if (isMechanismInclude(token)) {
                        mechanismListInclude.add(new MechanismInclude(token));
                    } else if (isModifierRedirect(token)) {
                        int index = token.indexOf("=") + 1;
                        redirectLocal = token.substring(index);
                    } else if (isModifierExplanation(token)) {
                        int index = token.indexOf("=") + 1;
                        explanationLocal = token.substring(index);
                    } else if ((fixed = extractIPv4CIDR(token)) != null) {
                        // Tenta recuperar um erro de sintaxe.
                        if (!visitedTokens.contains(token = "ip4:" + fixed)) {
                            mechanismListIP.add(new MechanismIPv4(token));
                        }
                        errorRegistry = true;
                    } else if ((fixed = extractIPv6CIDR(token)) != null) {
                        // Tenta recuperar um erro de sintaxe.
                        if (!visitedTokens.contains(token = "ip4:" + fixed)) {
                            mechanismListIP.add(new MechanismIPv6(token));
                        }
                        errorRegistry = true;
                    } else {
                        // Um erro durante o processamento foi encontrado.
                        Server.logDebug("SPF token not defined: " + token);
                        errorRegistry = true;
                        errorQuery = true;
                    }
                    visitedTokens.add(token);
                }
                if (result == null) {
                    result = (errorRegistry ? "ERR" : "OK") + " \"" + registry + "\"";
                } else {
                    result += (errorRegistry ? "\\nERR" : "\\nOK") + " \"" + registry + "\"";
                }
            }
            // Considerar os mecanismos na ordem crescente
            // de complexidade de processamento.
            ArrayList<Mechanism> mechanismListLocal = new ArrayList<Mechanism>();
            mechanismListLocal.addAll(mechanismListIP);
            mechanismListLocal.addAll(mechanismListDNS);
            mechanismListLocal.addAll(mechanismListInclude);
            mechanismListLocal.addAll(mechanismListPTR);
            // Atribuição dos novos valores.
            this.mechanismList = mechanismListLocal;
            this.all = allLocal;
            this.redirect = redirectLocal;
            this.explanation = explanationLocal;
            this.error = errorQuery;
            CacheSPF.CHANGED = true;
            this.queries = 0;
            this.nxdomain = 0;
            updateLastRefresh();
            Server.logLookupSPF(time, hostname, result);
        }
    }

    /**
     * Verifica se o whois é um mecanismo all válido.
     *
     * @param token o whois a ser verificado.
     * @return verdadeiro se o whois é um mecanismo all válido.
     */
    private static boolean isMechanismAll(String token) {
        return Pattern.matches(
                "^(\\+|-|~|\\?)?all$", token.toLowerCase());
    }

    /**
     * Verifica se o whois é um mecanismo ip4 válido.
     *
     * @param token o whois a ser verificado.
     * @return verdadeiro se o whois é um mecanismo ip4 válido.
     */
    private static boolean isMechanismIPv4(String token) {
        return Pattern.matches(
                "^((\\+|-|~|\\?)?ipv?4?:)?"
                + "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}"
                + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
                + "(/[0-9]{1,2})?"
                + "$", token.toLowerCase());
    }

    /**
     * Extrai um CIDR de IPv4 válido.
     *
     * @param token o whois a ser verificado.
     * @return um CIDR de IPv4 válido.
     */
    private static String extractIPv4CIDR(String token) {
        Pattern pattern = Pattern.compile(
                "(:|^)((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}"
                + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
                + "(/[0-9]{1,2})?)$");
        Matcher matcher = pattern.matcher(token.toLowerCase());
        if (matcher.find()) {
            return matcher.group(2);
        } else {
            return null;
        }
    }

    /**
     * Verifica se o whois é um mecanismo ip6 válido.
     *
     * @param token o whois a ser verificado.
     * @return verdadeiro se o whois é um mecanismo ip6 válido.
     */
    private static boolean isMechanismIPv6(String token) {
        return Pattern.matches(
                "^((\\+|-|~|\\?)?ipv?6?:)?"
                + "((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|"
                + "(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|"
                + "((25[0-5]|2[0-4]d|1dd|[1-9]?d)"
                + "(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|"
                + "(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:"
                + "((25[0-5]|2[0-4]d|1dd|[1-9]?d)"
                + "(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|"
                + "(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|"
                + "((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)"
                + "(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|"
                + "(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|"
                + "((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)"
                + "(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|"
                + "(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|"
                + "((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)"
                + "(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|"
                + "(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|"
                + "((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)"
                + "(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|"
                + "(:(((:[0-9A-Fa-f]{1,4}){1,7})|"
                + "((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)"
                + "(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))"
                + "(%.+)?(\\/[0-9]{1,3})?"
                + "$", token);
    }

    /**
     * Extrai um CIDR de IPv6 válido.
     *
     * @param token o whois a ser verificado.
     * @return um CIDR de IPv6 válido.
     */
    private static String extractIPv6CIDR(String token) {
        Pattern pattern = Pattern.compile(
                "(:|^)(((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|"
                + "(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|"
                + "((25[0-5]|2[0-4]d|1dd|[1-9]?d)"
                + "(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|"
                + "(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:"
                + "((25[0-5]|2[0-4]d|1dd|[1-9]?d)"
                + "(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|"
                + "(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|"
                + "((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)"
                + "(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|"
                + "(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|"
                + "((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)"
                + "(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|"
                + "(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|"
                + "((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)"
                + "(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|"
                + "(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|"
                + "((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)"
                + "(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|"
                + "(:(((:[0-9A-Fa-f]{1,4}){1,7})|"
                + "((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)"
                + "(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))"
                + "(%.+)?(\\/[0-9]{1,3})?)$");
        Matcher matcher = pattern.matcher(token);
        if (matcher.find()) {
            return matcher.group(2);
        } else {
            return null;
        }
    }

    private static String expand(String hostname,
            String ip, String sender, String helo) {
        int index = sender.indexOf('@');
        String local = sender.substring(0, index);
        String domain = sender.substring(index + 1);
        hostname = hostname.replace("%{i}", ip);
        hostname = hostname.replace("%{h}", helo.startsWith(".") ? helo.substring(1) : helo);
        hostname = hostname.replace("%{l}", local);
        hostname = hostname.replace("%{o}", domain);
        hostname = hostname.replace("%{d}", domain);
        hostname = hostname.replace("%{s}", sender.replace('@', '.'));
        hostname = hostname.replace("%{ir}", Subnet.reverse(ip));
        return hostname;
    }

    /**
     * Verifica se o whois é um mecanismo a válido.
     *
     * @param token o whois a ser verificado.
     * @return verdadeiro se o whois é um mecanismo a válido.
     */
    private static boolean isMechanismA(String token) {
        token = expand(token, "127.0.0.1", "sender@domain.tld", "host.domain.tld");
        return Pattern.matches(
                "^"
                + "(\\+|-|~|\\?)?a"
                + "(:(?=.{1,255}$)[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?(?:\\.[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?)*\\.?)?"
                + "(/[0-9]{1,2})?(//[0-9]{1,3})?"
                + "$", token.toLowerCase());
    }

    /**
     * Verifica se o whois é um mecanismo mx válido.
     *
     * @param token o whois a ser verificado.
     * @return verdadeiro se o whois é um mecanismo mx válido.
     */
    private static boolean isMechanismMX(String token) {
        token = expand(token, "127.0.0.1", "sender@domain.tld", "host.domain.tld");
        return Pattern.matches(
                "^(\\+|-|~|\\?)?mx"
                + "(:(?=.{1,255}$)[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?(?:\\.[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?)*\\.?)?"
                + "(\\.|/[0-9]{1,2})?(//[0-9]{1,3})?"
                + "$", token.toLowerCase());
    }

    /**
     * Verifica se o whois é um mecanismo ptr válido.
     *
     * @param token o whois a ser verificado.
     * @return verdadeiro se o whois é um mecanismo ptr válido.
     */
    private static boolean isMechanismPTR(String token) {
        token = expand(token, "127.0.0.1", "sender@domain.tld", "host.domain.tld");
        return Pattern.matches(
                "^(\\+|-|~|\\?)?ptr"
                + "(:(?=.{1,255}$)[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?(?:\\.[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?)*\\.?)?"
                + "$", token.toLowerCase());
    }

    /**
     * Verifica se o whois é um mecanismo existis válido.
     *
     * @param token o whois a ser verificado.
     * @return verdadeiro se o whois é um mecanismo existis válido.
     */
    private static boolean isMechanismExistis(String token) {
        token = expand(token, "127.0.0.1", "sender@domain.tld", "host.domain.tld");
        return Pattern.matches(
                "^(\\+|-|~|\\?)?exists:"
                + "((?=.{1,255}$)[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?(?:\\.[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?)*\\.?)"
                + "$", token.toLowerCase());
    }

    /**
     * Verifica se o whois é um mecanismo include válido.
     *
     * @param token o whois a ser verificado.
     * @return verdadeiro se o whois é um mecanismo include válido.
     */
    private static boolean isMechanismInclude(String token) {
        token = expand(token, "127.0.0.1", "sender@domain.tld", "host.domain.tld");
        return Pattern.matches(
                "^(\\+|-|~|\\?)?include:"
                + "(\\.?(?=.{1,255}$)[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?(?:\\.[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?)*\\.?)"
                + "$", token.toLowerCase());
    }

    /**
     * Verifica se o whois é um modificador redirect válido.
     *
     * @param token o whois a ser verificado.
     * @return verdadeiro se o whois é um modificador redirect válido.
     */
    private static boolean isModifierRedirect(String token) {
        token = expand(token, "127.0.0.1", "sender@domain.tld", "host.domain.tld");
        return Pattern.matches(
                "^redirect="
                + "((?=.{1,255}$)[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?(?:\\.[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?)*\\.?)"
                + "$", token.toLowerCase());
    }

    /**
     * Verifica se o whois é um modificador explanation válido.
     *
     * @param token o whois a ser verificado.
     * @return verdadeiro se o whois é um modificador explanation válido.
     */
    private static boolean isModifierExplanation(String token) {
        token = expand(token, "127.0.0.1", "sender@domain.tld", "host.domain.tld");
        return Pattern.matches(
                "^exp="
                + "((?=.{1,255}$)[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?(?:\\.[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?)*\\.?)"
                + "$", token.toLowerCase());
    }

    /**
     * Verifica se o registro atual expirou.
     *
     * @return verdadeiro se o registro atual expirou.
     */
    public boolean isRegistryExpired() {
        int expiredTime = (int) (System.currentTimeMillis() - lastRefresh) / Server.DAY_TIME;
        return expiredTime > REFRESH_TIME;
    }
    
    /**
     * Verifica se o registro atual expirou.
     *
     * @return verdadeiro se o registro atual expirou.
     */
    public boolean isRegistryExpired7() {
        int expiredTime = (int) (System.currentTimeMillis() - lastRefresh) / Server.DAY_TIME * 7;
        return expiredTime > REFRESH_TIME;
    }
    
    /**
     * Verifica se o registro atual expirou.
     *
     * @return verdadeiro se o registro atual expirou.
     */
    public boolean isRegistryExpired14() {
        int expiredTime = (int) (System.currentTimeMillis() - lastRefresh) / Server.DAY_TIME * 14;
        return expiredTime > REFRESH_TIME;
    }

    /**
     * Retorna o resultado SPF para um IP especifico.
     *
     * @param ip o IP a ser verificado.
     * @return o resultado SPF para um IP especifico.
     * @throws ProcessException se houver falha no processamento.
     */
    public String getResult(String ip, String sender, String helo,
            LinkedList<String> logList) throws ProcessException {
        Qualifier qualifier = getQualifier(
                ip, sender, helo, 0,
                new TreeSet<String>(), logList
        );
        if (qualifier == null) {
            return "NONE";
        } else {
            return qualifier.name();
        }
    }
    
    private void logRedirect(String redirect, Qualifier qualifier, LinkedList<String> logList) {
        if (logList != null) {
            logList.add(getHostname() + ":redirect:" + redirect + " => " + (qualifier == null ? "NOT MATCH" : qualifier.name()));
        }
    }
    
    private void logRedirect(String redirect, String message, LinkedList<String> logList) {
        if (logList != null) {
            logList.add(getHostname() + ":redirect:" + redirect + " => " + message);
        }
    }
    
    private void logError(Qualifier qualifier, LinkedList<String> logList) {
        if (logList != null) {
            logList.add(getHostname() + ":error => " + (qualifier == null ? "NOT MATCH" : qualifier.name()));
        }
    }
    
    private void logAll(Qualifier qualifier, LinkedList<String> logList) {
        if (logList != null) {
            logList.add(getHostname() + ":all => " + (qualifier == null ? "NOT MATCH" : qualifier.name()));
        }
    }
    
    private void logMechanism(Mechanism mechanism, Qualifier qualifier, LinkedList<String> logList) {
        if (logList != null) {
            logList.add(getHostname() + ":" + mechanism + " => " + (qualifier == null ? "NOT MATCH" : qualifier.name()));
        }
    }

    /**
     * Retorna o qualificador para uma consulta SPF.
     *
     * @param ip o IP a ser verificado.
     * @param deep a profundiade de navegação da ávore SPF.
     * @param hostVisitedSet o conjunto de hosts visitados.
     * @return o qualificador da consulta SPF.
     * @throws ProcessException se houver falha no processamento.
     */
    private Qualifier getQualifier(String ip, String sender, String helo,
            int deep, TreeSet<String> hostVisitedSet,
            LinkedList<String> logList) throws ProcessException {
        if (deep > 10) {
            return null; // Evita excesso de consultas.
        } else if (hostVisitedSet.contains(getHostname())) {
            return null; // Evita looping infinito.
        } else if (mechanismList == null) {
            throw new ProcessException("ERROR: HOST NOT FOUND");
        } else //            if (redirect == null)
        {
            hostVisitedSet.add(getHostname());
            for (Mechanism mechanism : mechanismList) {
                if (mechanism instanceof MechanismInclude) {
                    try {
                        MechanismInclude include = (MechanismInclude) mechanism;
                        Qualifier qualifier = include.getQualifierSPF(
                                ip, sender, helo, deep + 1, hostVisitedSet, logList);
                        if (qualifier == null) {
                            // Nenhum qualificador foi definido
                            // então continuar busca.
                        } else {
                            return qualifier;
                        }
                    } catch (ProcessException ex) {
                        if (ex.getMessage().equals("ERROR: HOST NOT FOUND")) {
                            // Não foi possível fazer o include.
                            // O hostname mencionado não existe.
                            // Continuar a verificação dos demais mecanismos.
                        } else {
                            throw ex;
                        }
                    }
                } else if (mechanism instanceof MechanismPTR) {
                    if (deep == 0 && mechanism.match(ip, sender, helo)) {
                        // Mecanismo PTR só será processado
                        // no primeiro nível da árvore.
                        Qualifier qualifier = mechanism.getQualifier();
                        logMechanism(mechanism, qualifier, logList);
                        return qualifier;
                    } else {
                        logMechanism(mechanism, null, logList);
                    }
                } else if (mechanism.match(ip, sender, helo)) {
                    Qualifier qualifier = mechanism.getQualifier();
                    logMechanism(mechanism, qualifier, logList);
                    return qualifier;
                } else {
                    logMechanism(mechanism, null, logList);
                }
            }
            if (redirect != null) {
//                hostVisitedSet.add(getHostname());
                SPF spf = CacheSPF.get(redirect);
                if (spf == null) {
                    logRedirect(redirect, "NOT FOUND", logList);
                    return null;
                } else {
                    Qualifier qualifier = spf.getQualifier(ip, sender, helo, 0, hostVisitedSet, logList);
                    logRedirect(redirect, qualifier, logList);
                    return qualifier;
                }
            } else if (error) {
//                // Foi encontrado um erro em algum mecanismos
//                // na qual os demais não tiveram macth.
//                throw new ProcessException("ERROR: SPF PARSE");

                // Nova interpretação SPF para erro de sintaxe.
                // Em caso de erro, retornar SOFTFAIL.
                logError(Qualifier.SOFTFAIL, logList);
                return Qualifier.SOFTFAIL;
            } else if (deep > 0) {
                // O mecanismo all só deve ser
                // processado no primeiro nível da árvore.
                return null;
            } else {
                // Retorna o qualificador do mecanismo all.
                // Pode ser nulo caso o registro não apresente o mecanismo all.
                logAll(all, logList);
                return all;
            }
//        } else {
//            hostVisitedSet.add(getHostname());
//            SPF spf = CacheSPF.get(redirect);
//            return spf.getQualifier(ip, sender, helo, 0, hostVisitedSet);
        }
    }

    /**
     * Retorna o hostname do registro SPF.
     *
     * @return o hostname do registro SPF.
     */
    public String getHostname() {
        return hostname;
    }

    /**
     * Retorna o dominio de explicação do registro SPF. Não sei ainda do que se
     * trata.
     *
     * @return o dominio de explicação do registro SPF.
     */
    public String getExplanation() {
        return explanation;
    }

    /**
     * A enumeração que representa todos os qualificadores possíveis.
     */
    private enum Qualifier {

        PASS("Pass"),
        FAIL("Fail"),
        SOFTFAIL("SoftFail"),
        NEUTRAL("Neutral");
        private final String description;

        private Qualifier(String description) {
            this.description = description;
        }

        @Override
        public String toString() {
            return description;
        }
    }

    /**
     * Classe abstrata que representa qualquer mecanismo de processamento SPF.
     */
    private abstract class Mechanism implements Serializable {

        private static final long serialVersionUID = 1L;
        private final String expression;
        private final Qualifier qualifier;

        private Mechanism(String expression) {
            this.expression = expression;
            switch (expression.charAt(0)) {
                case '+':
                    this.qualifier = Qualifier.PASS;
                    break;
                case '-':
                    this.qualifier = Qualifier.FAIL;
                    break;
                case '~':
                    this.qualifier = Qualifier.SOFTFAIL;
                    break;
                case '?':
                    this.qualifier = Qualifier.NEUTRAL;
                    break;
                default:
                    this.qualifier = Qualifier.PASS; // Default qualifier.
            }
        }

        public abstract boolean match(String ip,
                String sender, String helo) throws ProcessException;

        public Qualifier getQualifier() {
            return qualifier;
        }

        public String getExpression() {
            return expression;
        }

        public boolean equals(Mechanism other) {
            if (other == null) {
                return false;
            } else if (this.qualifier != other.qualifier) {
                return false;
            } else {
                return this.expression.equals(other.expression);
            }
        }

        @Override
        public String toString() {
            return expression;
        }
    }

    /**
     * Mecanismo de processamento CIDR de IPv4.
     */
    private final class MechanismIPv4 extends Mechanism {

        private static final long serialVersionUID = 1L;
        private final int address;
        private final int mask;
        /**
         * Marcado sempre que o mecanismo aponta para blocos reservados.
         */
        private final boolean reserved;

        public MechanismIPv4(String expression) {
            super(expression);
            int index = expression.indexOf(':');
            String inetnum = expression.substring(index + 1);
            index = inetnum.indexOf('/');
            int addressLocal;
            int maskLocal;
            if (index == -1) {
                maskLocal = 0xFFFFFFFF;
                addressLocal = SubnetIPv4.getAddressIP(inetnum);
            } else {
                maskLocal = SubnetIPv4.getMaskNet(inetnum.substring(index + 1));
                addressLocal = SubnetIPv4.getAddressIP(inetnum.substring(0, index)) & maskLocal;
            }
            // Verifica se o endereço pertence a blocos reservados.
            boolean reservedLocal = addressLocal == 0xFFFFFFFF; // Broadcast
            reservedLocal = reservedLocal || (addressLocal & 0xFF000000) == 0x00000000; // RFC 1700 Rede corrente
            reservedLocal = reservedLocal || (addressLocal & 0xFF000000) == 0x0A000000; // RFC 1918 Rede Privada
            reservedLocal = reservedLocal || (addressLocal & 0xFF000000) == 0x0E000000; // RFC 1700 Rede Pública
            reservedLocal = reservedLocal || (addressLocal & 0xFF000000) == 0x27000000; // RFC 1797 Reservado
            reservedLocal = reservedLocal || (addressLocal & 0xFF000000) == 0x7F000000; // RFC 3330 Localhost
            reservedLocal = reservedLocal || (addressLocal & 0xFFFF0000) == 0x80000000; // RFC 3330 Reservado (IANA)
            reservedLocal = reservedLocal || (addressLocal & 0xFFFF0000) == 0xA9FE0000; // RFC 3927 Zeroconf
            reservedLocal = reservedLocal || (addressLocal & 0xFFF00000) == 0xAC100000; // RFC 1918 Rede privada
            reservedLocal = reservedLocal || (addressLocal & 0xFFFF0000) == 0xBFFF0000; // RFC 3330 Reservado (IANA)
            reservedLocal = reservedLocal || (addressLocal & 0xFFFFFF00) == 0xC0000200; // RFC 3330 Documentação
            reservedLocal = reservedLocal || (addressLocal & 0xFFFFFF00) == 0xC0586300; // RFC 3068 IPv6 para IPv4
            reservedLocal = reservedLocal || (addressLocal & 0xFFFF0000) == 0xC0A80000; // RFC 1918 Rede Privada
            reservedLocal = reservedLocal || (addressLocal & 0xFFFE0000) == 0xC6120000; // RFC 2544 Teste de benchmark de redes
            reservedLocal = reservedLocal || (addressLocal & 0xFFFFFF00) == 0xDFFFFF00; // RFC 3330 Reservado
            reservedLocal = reservedLocal || (addressLocal & 0xF0000000) == 0xE0000000; // RFC 3171 Multicasts (antiga rede Classe D)
            reservedLocal = reservedLocal || (addressLocal & 0xF0000000) == 0xF0000000; // RFC 1700 Reservado (antiga rede Classe E)
            // Verifica se algum endereço reservado pertence ao bloco do mecanismo.
            reservedLocal = reservedLocal || addressLocal == (0x0A000000 & maskLocal); // RFC 1918 Rede Privada
            reservedLocal = reservedLocal || addressLocal == (0x0E000000 & maskLocal); // RFC 1700 Rede Pública
            reservedLocal = reservedLocal || addressLocal == (0x27000000 & maskLocal); // RFC 1797 Reservado
            reservedLocal = reservedLocal || addressLocal == (0x7F000000 & maskLocal); // RFC 3330 Localhost
            reservedLocal = reservedLocal || addressLocal == (0x80000000 & maskLocal); // RFC 3330 Reservado (IANA)
            reservedLocal = reservedLocal || addressLocal == (0xA9FE0000 & maskLocal); // RFC 3927 Zeroconf
            reservedLocal = reservedLocal || addressLocal == (0xAC100000 & maskLocal); // RFC 1918 Rede privada
            reservedLocal = reservedLocal || addressLocal == (0xBFFF0000 & maskLocal); // RFC 3330 Reservado (IANA)
            reservedLocal = reservedLocal || addressLocal == (0xC0000200 & maskLocal); // RFC 3330 Documentação
            reservedLocal = reservedLocal || addressLocal == (0xC0586300 & maskLocal); // RFC 3068 IPv6 para IPv4
            reservedLocal = reservedLocal || addressLocal == (0xC0A80000 & maskLocal); // RFC 1918 Rede Privada
            reservedLocal = reservedLocal || addressLocal == (0xC6120000 & maskLocal); // RFC 2544 Teste de benchmark de redes
            reservedLocal = reservedLocal || addressLocal == (0xDFFFFF00 & maskLocal); // RFC 3330 Reservado
            reservedLocal = reservedLocal || addressLocal == (0xE0000000 & maskLocal); // RFC 3171 Multicasts (antiga rede Classe D)
            reservedLocal = reservedLocal || addressLocal == (0xF0000000 & maskLocal); // RFC 1700 Reservado (antiga rede Classe E)
            if (reservedLocal) {
                Server.logDebug("SPF mecanism reserved: " + expression);
            }
            // Associação dos atributos.
            this.address = addressLocal;
            this.mask = maskLocal;
            this.reserved = reservedLocal;
        }
        
        public boolean isReserved() {
            return reserved;
        }

        @Override
        public boolean match(String ip, String sender, String helo) {
            if (isReserved()) {
                // Sempre que estiver apontando para
                // blocos reservados, ignorar o mecanismo.
                return false;
            } else if (SubnetIPv4.isValidIPv4(ip)) {
                int address2 = SubnetIPv4.getAddressIP(ip);
                return address == (address2 & mask);
            } else {
                return false;
            }
        }
    }

    /**
     * Mecanismo de processamento CIDR de IPv6.
     */
    private final class MechanismIPv6 extends Mechanism {

        private static final long serialVersionUID = 1L;
        private final short[] address;
        private final short[] mask;

        public MechanismIPv6(String expression) {
            super(expression);
            String inetnum;
            int index = expression.indexOf(':');
            try {
                String first = expression.substring(0, index);
                Integer.parseInt(first, 16);
                inetnum = expression;
            } catch (NumberFormatException ex) {
                inetnum = expression.substring(index + 1);
            }
            index = inetnum.indexOf('/');
            if (index == -1) {
                this.mask = SubnetIPv6.getMaskIPv6(128);
                this.address = SubnetIPv6.split(inetnum);
            } else {
                this.mask = SubnetIPv6.getMaskIPv6(inetnum.substring(index + 1));
                this.address = SubnetIPv6.split(inetnum.substring(0, index), mask);
            }
        }

        @Override
        public boolean match(String ip, String sender, String helo) {
            if (SubnetIPv6.isValidIPv6(ip)) {
                short[] address2 = SubnetIPv6.split(ip);
                for (int i = 0; i < 8; i++) {
                    if (address[i] != (address2[i] & mask[i])) {
                        return false;
                    }
                }
                return true;
            } else {
                return false;
            }
        }
    }

    /**
     * Mecanismo de processamento do registro A.
     */
    private final class MechanismA extends Mechanism {

        private static final long serialVersionUID = 1L;
        private final ArrayList<Mechanism> mechanismList = new ArrayList<Mechanism>();
        private boolean loaded = false;
        
        public MechanismA(String expression, boolean load) {
            super(expression);
            if (load && !expression.contains("%")) {
                loadList("127.0.0.1", "sender@domain.tld", "host.domain.tld");
            }
        }
        
        private String getExpression(String ip, String sender, String helo) {
            String expression = getExpression();
            expression = expand(expression, ip, sender, helo);
            if (!Character.isLetter(expression.charAt(0))) {
                // Expressão com qualificador.
                // Extrair qualificador.
                expression = expression.substring(1);
            }
            if (expression.startsWith("a:")) {
                expression = expression.substring(2);
            } else if (expression.startsWith("a")) {
                expression = SPF.this.getHostname() + expression.substring(1);
            }
            return expression;
        }

        private synchronized void loadList(String ip, String sender, String helo) {
            if (!loaded) {
                long time = System.currentTimeMillis();
                // Carregamento de lista.
                String expression = getExpression(ip, sender, helo);
                String hostname = expression;
                String maskIPv4 = null;
                String maskIPv6 = null;
                int indexIPv6Prefix = hostname.indexOf("//");
                if (indexIPv6Prefix != -1) {
                    maskIPv6 = hostname.substring(indexIPv6Prefix + 2);
                    hostname = hostname.substring(0, indexIPv6Prefix);
                }
                int indexIPv4Prefix = hostname.indexOf('/');
                if (indexIPv4Prefix != -1) {
                    maskIPv4 = hostname.substring(indexIPv4Prefix + 1);
                    hostname = hostname.substring(0, indexIPv4Prefix);
                }
                try {
                    TreeSet<String> resultSet = new TreeSet<String>();
                    Attributes attributes = Server.getAttributesDNS(
                            hostname, new String[]{"A"});
                    Attribute attributeA = attributes.get("A");
                    if (attributeA != null) {
                        NamingEnumeration enumeration = attributeA.getAll();
                        while (enumeration.hasMoreElements()) {
                            String hostAddress = (String) enumeration.next();
                            int indexSpace = hostAddress.indexOf(' ') + 1;
                            hostAddress = hostAddress.substring(indexSpace);
                            if (!SubnetIPv4.isValidIPv4(hostAddress)) {
                                try {
                                    hostAddress = InetAddress.getByName(hostAddress).getHostAddress();
                                } catch (UnknownHostException ex) {
                                    // Registro A não encontrado.
                                }
                            }
                            if (maskIPv4 != null) {
                                hostAddress += "/" + maskIPv4;
                            }
                            mechanismList.add(new MechanismIPv4(hostAddress));
                            resultSet.add(hostAddress);
                        }
                    }
                    attributes = Server.getAttributesDNS(
                            hostname, new String[]{"AAAA"});
                    Attribute attributeAAAA = attributes.get("AAAA");
                    if (attributeAAAA != null) {
                        NamingEnumeration enumeration = attributeAAAA.getAll();
                        while (enumeration.hasMoreElements()) {
                            String hostAddress = (String) enumeration.next();
                            int indexSpace = hostAddress.indexOf(' ') + 1;
                            hostAddress = hostAddress.substring(indexSpace);
                            if (Domain.isHostname(hostAddress)) {
                                try {
                                    hostAddress = Inet6Address.getByName(hostAddress).getHostAddress();
                                } catch (UnknownHostException ex) {
                                    // Registro AAAA não encontrado.
                                    hostAddress = null;
                                }
                            }
                            if (SubnetIPv6.isValidIPv6(hostAddress)) {
                                if (maskIPv6 != null) {
                                    hostAddress += "/" + maskIPv6;
                                }
                                mechanismList.add(new MechanismIPv6(hostAddress));
                                resultSet.add(hostAddress);
                            }
                        }
                    }
                    Server.logMecanismA(time, expression, resultSet.toString());
                } catch (CommunicationException ex) {
                    Server.logMecanismA(time, expression, "TIMEOUT");
                } catch (NameNotFoundException ex) {
                    Server.logMecanismA(time, expression, "NOT FOUND");
                } catch (InvalidAttributeIdentifierException ex) {
                    Server.logMecanismA(time, expression, "NOT FOUND");
                } catch (NamingException ex) {
                    Server.logMecanismA(time, expression, "ERROR " + ex.getMessage());
                }
                if (!expression.contains("%")) {
                    loaded = true;
                }
            }
        }

        @Override
        public boolean match(String ip, String sender, String helo) throws ProcessException {
            loadList(ip, sender, helo);
            for (Mechanism mechanism : mechanismList) {
                if (mechanism.match(ip, sender, helo)) {
                    return true;
                }
            }
            return false;
        }
    }

    /**
     * Mecanismo de processamento do registro MX.
     */
    private final class MechanismMX extends Mechanism {

        private static final long serialVersionUID = 1L;
        private final ArrayList<Mechanism> mechanismList = new ArrayList<Mechanism>();
        private boolean loaded = false;
        
        public MechanismMX(String expression, boolean load) {
            super(expression);
            if (load && !expression.contains("%")) {
                loadList("127.0.0.1", "sender@domain.tld", "host.domain.tld");
            }
        }
        
        private String getExpression(String ip, String sender, String helo) {
            String expression = getExpression();
            expression = expand(expression, ip, sender, helo);
            if (!Character.isLetter(expression.charAt(0))) {
                // Expressão com qualificador.
                // Extrair qualificador.
                expression = expression.substring(1);
            }
            if (expression.startsWith("mx:")) {
                expression = expression.substring(3);
            } else if (expression.startsWith("mx")) {
                expression = SPF.this.getHostname() + expression.substring(2);
            }
            return expression;
        }

        private synchronized void loadList(String ip, String sender, String helo) {
            if (!loaded) {
                long time = System.currentTimeMillis();
                // Carregamento de lista.
                String expression = getExpression(ip, sender, helo);
                String hostname = expression;
                String maskIPv4 = null;
                String maskIPv6 = null;
                int indexIPv6Prefix = hostname.indexOf("//");
                if (indexIPv6Prefix != -1) {
                    maskIPv6 = hostname.substring(indexIPv6Prefix + 2);
                    hostname = hostname.substring(0, indexIPv6Prefix);
                }
                int indexIPv4Prefix = hostname.indexOf('/');
                if (indexIPv4Prefix != -1) {
                    maskIPv4 = hostname.substring(indexIPv4Prefix + 1);
                    hostname = hostname.substring(0, indexIPv4Prefix);
                }
                try {
                    TreeSet<String> resultSet = new TreeSet<String>();
                    Attributes attributesMX = Server.getAttributesDNS(
                            hostname, new String[]{"MX"});
                    Attribute attributeMX = attributesMX.get("MX");
                    if (attributeMX != null) {
                        NamingEnumeration enumeration = attributeMX.getAll();
                        while (enumeration.hasMoreElements()) {
                            String hostAddress = (String) enumeration.next();
                            int indexSpace = hostAddress.indexOf(' ') + 1;
                            hostAddress = hostAddress.substring(indexSpace);
                            if (SubnetIPv4.isValidIPv4(hostAddress)) {
                                if (maskIPv4 != null) {
                                    hostAddress += "/" + maskIPv4;
                                }
                                mechanismList.add(new MechanismIPv4(hostAddress));
                                resultSet.add(hostAddress);
                            } else if (SubnetIPv6.isValidIPv6(hostAddress)) {
                                if (maskIPv6 != null) {
                                    hostAddress += "/" + maskIPv6;
                                }
                                mechanismList.add(new MechanismIPv6(hostAddress));
                                resultSet.add(hostAddress);
                            } else {
                                try {
                                    Attributes attributesA = Server.getAttributesDNS(
                                            hostAddress, new String[]{"A"});
                                    Attribute attributeA = attributesA.get("A");
                                    if (attributeA != null) {
                                        for (int i = 0; i < attributeA.size(); i++) {
                                            String host4Address = (String) attributeA.get(i);
                                            if (SubnetIPv4.isValidIPv4(host4Address)) {
                                                if (maskIPv4 != null) {
                                                    host4Address += "/" + maskIPv4;
                                                }
                                                mechanismList.add(new MechanismIPv4(host4Address));
                                                resultSet.add(host4Address);
                                            }
                                        }
                                    }
                                    Attributes attributesAAAA = Server.getAttributesDNS(
                                            hostAddress, new String[]{"AAAA"});
                                    Attribute attributeAAAA = attributesAAAA.get("AAAA");
                                    if (attributeAAAA != null) {
                                        for (int i = 0; i < attributeAAAA.size(); i++) {
                                            String host6Address = (String) attributeAAAA.get(i);
                                            if (SubnetIPv6.isValidIPv6(host6Address)) {
                                                if (maskIPv6 != null) {
                                                    host6Address += "/" + maskIPv6;
                                                }
                                                mechanismList.add(new MechanismIPv6(host6Address));
                                                resultSet.add(host6Address);
                                            }
                                        }
                                    }
                                } catch (NamingException ex) {
                                    // Endereço não encontrado.
                                }
//                                if (indexPrefix == -1) {
//                                    // Se não houver definição CIDR,
//                                    // considerar também os endereços IPv6
//                                    // para ficar compatível com pilha dupla.
//                                    // Isto não é um padrão SPF mas não há
//                                    // prejuízo algum no uso deste conceito.
//                                    try {
//                                        Attributes attributesAAAA = Server.INITIAL_DIR_CONTEXT.getAttributes(
//                                                "dns:/" + hostAddress, new String[]{"AAAA"});
//                                        Attribute attributeAAAA = attributesAAAA.get("AAAA");
//                                        if (attributeAAAA != null) {
//                                            for (int i = 0; i < attributeAAAA.size(); i++) {
//                                                String host6Address = (String) attributeAAAA.get(i);
//                                                if (SubnetIPv6.isValidIPv6(host6Address)) {
//                                                    mechanismList.add(new MechanismIPv6(host6Address));
//                                                    resultSet.add(host6Address);
//                                                }
//                                            }
//                                        }
//                                    } catch (NamingException ex) {
//                                        // Endereço não encontrado.
//                                    }
//                                }
                            }
                        }
                    }
                    Server.logMecanismMX(time, expression, resultSet.toString());
                } catch (CommunicationException ex) {
                    Server.logMecanismMX(time, expression, "TIMEOUT");
                } catch (NameNotFoundException ex) {
                    Server.logMecanismMX(time, expression, "NOT FOUND");
                } catch (InvalidAttributeIdentifierException ex) {
                    Server.logMecanismMX(time, expression, "NOT FOUND");
                } catch (NamingException ex) {
                    Server.logMecanismMX(time, expression, "ERROR " + ex.getMessage());
                }
                if (!getExpression().contains("%")) {
                    loaded = true;
                }
            }
        }

        @Override
        public boolean match(String ip, String sender, String helo) throws ProcessException {
            loadList(ip, sender, helo);
            for (Mechanism mechanism : mechanismList) {
                if (mechanism.match(ip, sender, helo)) {
                    return true;
                }
            }
            return false;
        }
    }

    /**
     * Mecanismo de processamento do reverso do IP de origem.
     */
    private final class MechanismPTR extends Mechanism {

        private static final long serialVersionUID = 1L;
        
        public MechanismPTR(String expression) {
            super(expression);
        }

        private String getHostname(String ip, String sender, String helo) {
            String expression = getExpression();
            int index = expression.indexOf(':');
            if (index == -1) {
                return SPF.this.getHostname();
            } else {
                expression = expression.substring(index + 1);
                expression = expand(expression, ip, sender, helo);
                return expression;
            }
        }

        @Override
        public synchronized boolean match(
                String ip, String sender,
                String helo) throws ProcessException {
            String hostname = getHostname(ip, sender, helo);
            int index = hostname.indexOf(':');
            if (index > 0) {
                hostname = "." + hostname.substring(index + 1);
            } else {
                hostname = "." + hostname;
            }
            for (String reverse : SPF.getReverse(ip)) {
                if (reverse.endsWith(hostname)) {
                    return true;
                }
            }
            return false;
        }
    }

    /**
     * Retorna o conjunto de hostnames que representam o DNS reverso do IP
     * informado. Apesar de geralmente haver apenas um reverso configurado, é
     * possível que haja mais de um pois é possível que haja mais de um registro
     * PTR e cada um deles apontando para o mesmo IP.
     *
     * @param ip o IP a ser verificado.
     * @return o conjunto de reversos do IP informado.
     */
    private static TreeSet<String> getReverse(String ip) {
        long time1 = System.currentTimeMillis();
        String reverse = null;
        TreeSet<String> reverseList = new TreeSet<String>();
        try {
            byte[] address1;
            if (SubnetIPv4.isValidIPv4(ip)) {
                reverse = "in-addr.arpa";
                address1 = SubnetIPv4.split(ip);
                for (byte octeto : address1) {
                    reverse = ((int) octeto & 0xFF) + "." + reverse;
                }
            } else if (SubnetIPv6.isValidIPv6(ip)) {
                reverse = "ip6.arpa";
                address1 = SubnetIPv6.splitByte(ip);
                for (byte octeto : address1) {
                    String hexPart = Integer.toHexString((int) octeto & 0xFF);
                    if (hexPart.length() == 1) {
                        hexPart = "0" + hexPart;
                    }
                    for (char digit : hexPart.toCharArray()) {
                        reverse = digit + "." + reverse;
                    }
                }
            } else {
                throw new ProcessException("ERROR: DNS REVERSE");
            }
            Attributes atributes = Server.getAttributesDNS(
                    reverse, new String[]{"PTR"});
            Attribute attributePTR = atributes.get("PTR");
            for (int indexPTR = 0; indexPTR < attributePTR.size(); indexPTR++) {
                try {
                    String host = (String) attributePTR.get(indexPTR);
                    if (host.startsWith(".")) {
                        host = host.substring(1);
                    }
                    if (host.endsWith(".")) {
                        host = host.substring(0, host.length() - 1);
                    }
                    if (SubnetIPv4.isValidIPv4(ip)) {
                        atributes = Server.getAttributesDNS(
                                host, new String[]{"A"});
                        Attribute attributeA = atributes.get("A");
                        for (int indexA = 0; indexA < attributeA.size(); indexA++) {
                            String ipA = (String) attributeA.get(indexA);
                            byte[] address2 = SubnetIPv4.split(ipA);
                            if (Arrays.equals(address1, address2)) {
                                reverseList.add("." + host);
                                break;
                            }
                        }
                    } else if (SubnetIPv6.isValidIPv6(ip)) {
                        atributes = Server.getAttributesDNS(
                                host, new String[]{"AAAA"});
                        Attribute attributeAAAA = atributes.get("AAAA");
                        for (int indexAAAA = 0; indexAAAA < attributeAAAA.size(); indexAAAA++) {
                            String ipAAAA = (String) attributeAAAA.get(indexAAAA);
                            byte[] address2 = SubnetIPv6.splitByte(ipAAAA);
                            if (Arrays.equals(address1, address2)) {
                                reverseList.add("." + host);
                                break;
                            }
                        }
                    }
                } catch (NamingException ex) {
                    // Endereço não encontrado.
                }
            }
            Server.logReverseDNS(time1, ip, reverseList.toString());
        } catch (CommunicationException ex) {
            Server.logReverseDNS(time1, ip, "TIMEOUT");
        } catch (NameNotFoundException ex) {
            Server.logReverseDNS(time1, ip, "NOT FOUND");
        } catch (InvalidAttributeIdentifierException ex) {
            Server.logReverseDNS(time1, ip, "NOT FOUND");
        } catch (NamingException ex) {
            Server.logReverseDNS(time1, ip, "ERROR " + ex.getMessage());
        } finally {
            return reverseList;
        }
    }

    /**
     * Mecanismo de processamento exists.
     */
    private final class MechanismExists extends Mechanism {

        private static final long serialVersionUID = 1L;
        
        public MechanismExists(String expression) {
            super(expression);
        }

        private String getHostname(String ip, String sender, String helo) {
            String expression = getExpression();
            int index = expression.indexOf(':') + 1;
            expression = expression.substring(index);
            expression = expand(expression, ip, sender, helo);
            return expression;
        }

        @Override
        public boolean match(String ip, String sender, String helo) throws ProcessException {
            long time = System.currentTimeMillis();
            String hostname = getHostname(ip, sender, helo);
            try {
                Server.getAttributesDNS(
                        hostname, new String[]{"A"});
                Server.logMecanismA(time, hostname, "EXISTS");
                return true;
            } catch (CommunicationException ex) {
                Server.logMecanismA(time, hostname, "TIMEOUT");
                return false;
            } catch (NameNotFoundException ex) {
                Server.logMecanismA(time, hostname, "NOT FOUND");
                return false;
            } catch (InvalidAttributeIdentifierException ex) {
                Server.logMecanismA(time, hostname, "NOT FOUND");
                return false;
            } catch (NamingException ex) {
                Server.logMecanismA(time, hostname, "ERROR " + ex.getMessage());
                return false;
            }
        }
    }

    /**
     * Mecanismo de inclusão de um nó na árvore SPF.
     */
    private final class MechanismInclude extends Mechanism {

        private static final long serialVersionUID = 1L;

        public MechanismInclude(String expression) {
            super(expression);
        }

        private String getHostname(String ip, String sender, String helo) {
            String expression = getExpression();
            int index = expression.indexOf(':') + 1;
            expression = expression.substring(index);
            expression = expand(expression, ip, sender, helo);
            return expression;
        }

        private Qualifier getQualifierSPF(
                String ip, String sender, String helo,
                int deep, TreeSet<String> hostVisitedSet,
                LinkedList<String> logList) throws ProcessException {
            String hostname = getHostname(ip, sender, helo);
            SPF spf = CacheSPF.get(hostname);
            if (spf == null) {
                return null;
            } else {
                return spf.getQualifier(ip, sender, helo, deep, hostVisitedSet, logList);
            }

        }

        @Override
        public boolean match(String ip, String sender, String helo) throws ProcessException {
            throw new ProcessException("ERROR: FATAL ERROR"); // Não pode fazer o match direto.
        }
    }

    @Override
    public String toString() {
        return hostname + " " + mechanismList + " " + redirect + " " + all;
    }

    /**
     * Classe que representa o cache de registros SPF.
     */
    private static class CacheSPF {

        /**
         * Mapa para cache dos registros SPF consultados.
         */
        private static final HashMap<String,SPF> MAP = new HashMap<String,SPF>();
        /**
         * O próximo registro SPF que deve ser atualizado.
         */
        private static SPF spfRefresh = null;
        /**
         * Flag que indica se o cache foi modificado.
         */
        private static boolean CHANGED = false;
        
        private static synchronized boolean isChanged() {
            return CHANGED;
        }
        
        private static synchronized void setNotChanged() {
            CHANGED = false;
        }
        
        private static synchronized SPF dropExact(String token) {
            SPF ret = MAP.remove(token);
            if (ret != null) {
                CHANGED = true;
            }
            return ret;
        }

        private static synchronized SPF putExact(String key, SPF value) {
            SPF ret = MAP.put(key, value);
            if (!value.equals(ret)) {
                CHANGED = true;
            }
            return ret;
        }
        
        private static synchronized TreeSet<String> keySet() {
            TreeSet<String> keySet = new TreeSet<String>();
            keySet.addAll(MAP.keySet());
            return keySet;
        }
        
        private static synchronized HashMap<String,SPF> getMap() {
            HashMap<String,SPF> map = new HashMap<String,SPF>();
            map.putAll(MAP);
            return map;
        }
        
        private static synchronized SPF getExact(String host) {
            return MAP.get(host);
        }
        
        private static synchronized Collection<SPF> getValues() {
            return MAP.values();
        }
        
        private static synchronized SPF getRefreshSPF() {
            SPF spf = spfRefresh;
            spfRefresh = null;
            return spf;
        }
        
        private static synchronized void addQuerie(SPF spf) {
            spf.queries++;
            if (spfRefresh == null) {
                spfRefresh = spf;
            } else if (spfRefresh.queries < spf.queries) {
                spfRefresh = spf;
            }
        }
        
        private static void dropExpired() {
            for (String host : keySet()) {
                long time = System.currentTimeMillis();
                SPF spf = getExact(host);
                if (spf != null && spf.isRegistryExpired14()) {
                    spf = dropExact(host);
                    if (spf != null) {
                        Server.logLookupSPF(time, host, "EXPIRED");
                    }
                }
            }
        }

        /**
         * Adiciona um registro SPF no mapa de cache.
         *
         * @param spf o registro SPF para ser adocionado.
         */
        private static void add(SPF spf) {
            putExact(spf.getHostname(), spf);
        }

        private static boolean refresh(String address,
                boolean load) throws ProcessException {
            String host = Domain.extractHost(address, false);
            if (host == null) {
                return false;
            } else {
                SPF spf = getExact(host);
                if (spf == null) {
                    return false;
                } else {
                    spf.refresh(load, false);
                    return true;
                }
            }
        }

        /**
         * Retorna o registro SPF do e-mail.
         *
         * @param address o endereço de e-mail que deve ser consultado.
         * @return o registro SPF, se for encontrado.
         * @throws ProcessException se houver falha no processamento.
         */
        private static SPF get(String address) throws ProcessException {
            String host = Domain.extractHost(address, false);
            if (host == null) {
                return null;
            } else {
                SPF spf = getExact(host);
                if (spf == null) {
                    spf = new SPF(host);
                    add(spf);
                } else if (spf.isRegistryExpired()) {
                    try {
                        // Atualiza o registro se ele for antigo demais.
                        spf.refresh(false, false);
                    } catch (ProcessException ex) {
                        if (ex.getMessage().equals("ERROR: DNS UNAVAILABLE")) {
                            // Manter registro anterior quando houver erro de DNS.
                            Server.logDebug(address + ": SPF temporarily unavailable.");
                        } else {
                            throw ex;
                        }
                    }
                }
//                spf.queries++; // Incrementa o contador de consultas.
                addQuerie(spf); // Incrementa o contador de consultas.
                return spf;
            }
        }

        private static void store() {
            if (isChanged()) {
                try {
                    long time = System.currentTimeMillis();
                    File file = new File("./data/spf.map");
                    HashMap<String,SPF> map = getMap();
                    FileOutputStream outputStream = new FileOutputStream(file);
                    try {
                        SerializationUtils.serialize(map, outputStream);
                        setNotChanged();
                    } finally {
                        outputStream.close();
                    }
                    Server.logStore(time, file);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }

        private static void load() {
            long time = System.currentTimeMillis();
            File file = new File("./data/spf.map");
            if (file.exists()) {
                try {
                    HashMap<String,Object> map;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        map = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    for (String key : map.keySet()) {
                        Object value = map.get(key);
                        if (value instanceof SPF) {
                            SPF spf = (SPF) value;
                            putExact(key, spf);
                        }
                    }
                    setNotChanged();
                    Server.logLoad(time, file);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }
        
        /**
         * Atualiza o registro mais consultado.
         */
        private static void refresh() {
            SPF spfMax = getRefreshSPF();
            if (spfMax == null) {
                for (SPF spf : getValues()) {
                    if (spfMax == null) {
                        spfMax = spf;
                    } else if (spfMax.queries < spf.queries) {
                        spfMax = spf;
                    }
                }
            }
            if (spfMax != null && spfMax.queries > 3) {
                try {
                    spfMax.refresh(true, false);
                } catch (ProcessException ex) {
                    spfMax.updateLastRefresh();
                    if (ex.getMessage().equals("ERROR: HOST NOT FOUND")) {
                        Server.logDebug(spfMax.getHostname() + ": SPF registry cache removed.");
                    } else if (ex.getMessage().equals("ERROR: DNS UNAVAILABLE")) {
                        // Manter registro anterior quando houver erro de DNS.
                        Server.logDebug(spfMax.getHostname() + ": SPF temporarily unavailable.");
                    } else {
                        Server.logError(ex);
                    }
                }
            }
        }
    }
    
    public static void dropExpiredSPF() {
        CacheSPF.dropExpired();
    }
    
    public static void refreshSPF() {
        CacheSPF.refresh();
    }
    public static void refreshHELO() {
        CacheHELO.refresh();
    }
    
    
//    private static final Semaphore REFRESH_SEMAPHORE = new Semaphore(1);

//    /**
//     * Atualiza registros SPF somente se nenhum outro processo estiver
//     * atualizando.
//     */
//    public static void tryRefresh() {
//        // Evita que muitos processos fiquem
//        // presos aguardando a liberação do método.
//        if (REFRESH_SEMAPHORE.tryAcquire()) {
//            try {
//                CacheSPF.refresh();
//                CacheHELO.refresh();
//            } finally {
//                REFRESH_SEMAPHORE.release();
//            }
//        }
//    }
    
    /**
     * Classe que representa o cache de registros de denúncia.
     */
    private static class CacheComplain {

        /**
         * Mapa de reclamações com seus respectivos tickets.
         */
        private static final TreeMap<Long,String> MAP = new TreeMap<Long,String>();
        
        /**
         * Flag que indica se o cache de reclamações foi modificado.
         */
        private static boolean CHANGED = false;
        
        private static synchronized boolean dropExact(long time) {
            if (MAP.remove(time) == null) {
                return false;
            } else {
                CHANGED = true;
                return true;
            }
        }
        
        private static synchronized boolean putExact(long time, String tokens) {
            if (tokens == null) {
                return false;
            } else if (tokens.equals(MAP.put(time, tokens))) {
                return false;
            } else {
                CHANGED = true;
                return true;
            }
        }
        
        private static synchronized TreeMap<Long,String> getMap() {
            TreeMap<Long,String> map = new TreeMap<Long,String>();
            map.putAll(MAP);
            return map;
        }
        
        private static synchronized TreeMap<Long,String> headMap(long end) {
            TreeMap<Long,String> head = new TreeMap<Long,String>();
            head.putAll(MAP.headMap(end));
            return head;
        }
        
        private static TreeMap<Long,String> extractHeadMap(long end) {
            TreeMap<Long,String> map = new TreeMap<Long,String>();
            TreeMap<Long,String> head = headMap(end);
            for (long time : head.keySet()) {
                String tokens = head.get(time);
                if (dropExact(time)) {
                    map.put(time, tokens);
                }
            }
            return map;
        }

        private static void store() {
            if (CHANGED) {
                try {
                    long time = System.currentTimeMillis();
                    File file = new File("./data/complain.map");
                    TreeMap<Long,String> map = getMap();
                    FileOutputStream outputStream = new FileOutputStream(file);
                    try {
                        SerializationUtils.serialize(map, outputStream);
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

        private static void load() {
            long time = System.currentTimeMillis();
            File file = new File("./data/complain.map");
            if (file.exists()) {
                try {
                    Map<Long,String> map;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        map = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    for (Long date : map.keySet()) {
                        String tokens = map.get(date);
                        putExact(date, tokens);
                    }
                    CHANGED = false;
                    Server.logLoad(time, file);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }
        
        private static void dropExpired() {
            String client = null;
            long end = System.currentTimeMillis() - 604800000;
            TreeMap<Long,String> map = extractHeadMap(end);
            for (long time : map.keySet()) {
                String tokens = map.get(time);
                TreeSet<String> tokenSet = new TreeSet<String>();
                StringTokenizer tokenizer = new StringTokenizer(tokens, " ");
                while (tokenizer.hasMoreTokens()) {
                    String token = tokenizer.nextToken();
                    tokenSet.add(token);
                }
                for (String key : expandTokenSet(tokenSet)) {
                    Distribution distribution = CacheDistribution.get(key, false);
                    if (distribution != null && distribution.removeSpam()) {
                        Peer.sendToAll(key, distribution);
                    }
                }
                time += 604800000;
                Server.logQuery(time, "CLEAR", client, tokenSet);
            }
        }

        /**
         * Adiciona uma nova reclamação de SPAM.
         *
         * @param ticket o ticket da mensagem original.
         * @throws ProcessException se houver falha no processamento do ticket.
         */
        public static TreeSet<String> addComplain(String origin,
                String ticket) throws ProcessException {
            if (ticket == null) {
                return null;
            } else {
                long time = System.currentTimeMillis();
                TreeSet<String> tokenSet = new TreeSet<String>();
                TreeSet<String> blackSet = new TreeSet<String>();
                String registry = Server.decrypt(ticket);
                int index = registry.indexOf(' ');
                Date date = getTicketDate(registry.substring(0, index));
                if (System.currentTimeMillis() - date.getTime() > 432000000) {
                    // Ticket vencido com mais de 5 dias.
                    throw new ProcessException("TICKET EXPIRED");
                } else {
                    registry = registry.substring(index + 1);
                    StringTokenizer tokenizer = new StringTokenizer(registry, " ");
                    StringBuilder builder = new StringBuilder();
                    while (tokenizer.hasMoreTokens()) {
                        String token = tokenizer.nextToken();
                        tokenSet.add(token);
                        if (builder.length() > 0) {
                            builder.append(' ');
                        }
                        builder.append(token);
                    }
                    if (putExact(date.getTime(), builder.toString())) {
                        for (String key : expandTokenSet(tokenSet)) {
                            if (!CacheIgnore.contains(key)) {
                                Distribution distribution = CacheDistribution.get(key, true);
                                if (distribution.addSpam()) {
                                    Peer.sendToAll(key, distribution);
                                }
                                blackSet.add(key);
                                
                            }
                        }
                    } else {
                        // Ticket já denunciado.
                        return null;
                    }
                }
                Server.logQuery(time, "CMPLN", origin, ticket, blackSet);
                return blackSet;
            }
        }

        /**
         * Remove uma nova reclamação de SPAM.
         *
         * @param ticket o ticket da mensagem original.
         * @throws ProcessException se houver falha no processamento do ticket.
         */
        public static TreeSet<String> deleteComplain(
                String client, String ticket) throws ProcessException {
            if (ticket == null) {
                return null;
            } else {
                long time = System.currentTimeMillis();
                TreeSet<String> tokenSet = new TreeSet<String>();
                String registry = Server.decrypt(ticket);
                int index = registry.indexOf(' ');
                Date date = getTicketDate(registry.substring(0, index));
                if (dropExact(date.getTime())) {
                    registry = registry.substring(index + 1);
                    StringTokenizer tokenizer = new StringTokenizer(registry, " ");
                    while (tokenizer.hasMoreTokens()) {
                        String token = tokenizer.nextToken();
                        tokenSet.add(token);
                    }
                    for (String key : expandTokenSet(tokenSet)) {
                        Distribution distribution = CacheDistribution.get(key, false);
                        if (distribution != null && distribution.removeSpam()) {
                            Peer.sendToAll(key, distribution);
                        }
                    }
                    Server.logQuery(time, "CLEAR", client, tokenSet);
                    return tokenSet;
                } else {
                    // Ticket não foi denunciado.
                    return null;
                }
            }
        }
    }
    
    public static void dropExpiredComplain() {
        CacheComplain.dropExpired();
    }
    
    public static TreeSet<String> addComplain(String origin,
                String ticket) throws ProcessException {
        return CacheComplain.addComplain(origin, ticket);
    }
    
    public static TreeSet<String> deleteComplain(String origin,
                String ticket) throws ProcessException {
        return CacheComplain.deleteComplain(origin, ticket);
    }

    /**
     * Classe que representa o cache de registros de distribuição de
     * responsáveis.
     */
    private static class CacheDistribution {

        /**
         * Mapa de distribuição binomial dos tokens encontrados.
         */
        private static final TreeMap<String,Distribution> MAP = new TreeMap<String,Distribution>();
        /**
         * Flag que indica se o cache foi modificado.
         */
        private static boolean CHANGED = false;
        
        private static synchronized Distribution dropExact(String key) {
            Distribution ret = MAP.remove(key);
            if (ret != null) {
                CHANGED = true;
            }
            return ret;
        }

        private static synchronized Distribution putExact(String key, Distribution value) {
            Distribution ret = MAP.put(key, value);
            if (!value.equals(ret)) {
                CHANGED = true;
            }
            return ret;
        }
        
        private static synchronized TreeSet<String> keySet() {
            TreeSet<String> keySet = new TreeSet<String>();
            keySet.addAll(MAP.keySet());
            return keySet;
        }
        
        private static synchronized HashMap<String,Distribution> getMap() {
            HashMap<String,Distribution> map = new HashMap<String,Distribution>();
            map.putAll(MAP);
            return map;
        }
        
        private static synchronized NavigableMap<String,Distribution> getSubMap(
                String fromKey, String toKey) {
            return MAP.subMap(fromKey, false, toKey, false);
        }
        
        private static synchronized Distribution getExact(String host) {
            return MAP.get(host);
        }
        
        private static synchronized boolean isChanged() {
            return CHANGED;
        }
        
        private static synchronized void setStored() {
            CHANGED = false;
        }
        
        private static synchronized void setLoaded() {
            CHANGED = false;
        }

        private static void store() {
            if (isChanged()) {
                try {
                    long time = System.currentTimeMillis();
                    File file = new File("./data/distribution.map");
                    HashMap<String,Distribution> map = getMap();
                    FileOutputStream outputStream = new FileOutputStream(file);
                    try {
                        SerializationUtils.serialize(map, outputStream);
                        setStored();
                    } finally {
                        outputStream.close();
                    }
                    Server.logStore(time, file);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }

        private static void load() {
            long time = System.currentTimeMillis();
            File file = new File("./data/distribution.map");
            if (file.exists()) {
                try {
                    Map<String,Object> map;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        map = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    for (String key : map.keySet()) {
                        Object value = map.get(key);
                        if (value instanceof Distribution) {
                            Distribution distribution = (Distribution) value;
                            putExact(key.toLowerCase(), distribution);
                        }
                    }
                    setLoaded();
                    Server.logLoad(time, file);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }

        private static void dropExpired() {
            TreeSet<String> distributionKeySet = new TreeSet<String>();
            distributionKeySet.addAll(keySet());
            for (String token : distributionKeySet) {
                long time = System.currentTimeMillis();
                Distribution distribution = getExact(token);
                if (distribution != null
                        && distribution.hasLastQuery()
                        && distribution.isExpired14()) {
                    distribution = drop(token);
                    if (distribution != null) {
                        Server.log(time, "REPTN", token, "EXPIRED");
                    }
                }
            }
        }

        private static Distribution drop(String key) {
            Distribution distribution = dropExact(key);
            if (distribution != null) {
                CacheBlock.dropExact(key);
                Peer.sendToAll(key, null);
            }
            return distribution;
        }
        
        private synchronized static TreeMap<String,Distribution> getAll(String value) {
            TreeMap<String,Distribution> map = new TreeMap<String,Distribution>();
            NavigableMap<String,Distribution> subMap;
            Distribution distribution;
            if (Subnet.isValidIP(value)) {
                String ip = Subnet.normalizeIP(value);
                distribution = getExact(ip);
                map.put(ip, distribution);
            } else if (Subnet.isValidCIDR(value)) {
                String cidr = Subnet.normalizeCIDR(value);
                subMap = getSubMap("0", ":");
                for (String ip : subMap.keySet()) {
                    if (Subnet.containsIP(cidr, ip)) {
                        distribution = getExact(ip);
                        map.put(ip, distribution);
                    }
                }
                subMap = getSubMap("a", "g");
                for (String ip : subMap.keySet()) {
                    if (SubnetIPv6.containsIP(cidr, ip)) {
                        distribution = getExact(ip);
                        map.put(ip, distribution);
                    }
                }
            } else if (value.startsWith(".")) {
                String hostname = value;
                subMap = getSubMap(".", "/");
                for (String key : subMap.keySet()) {
                    if (key.endsWith(hostname)) {
                        distribution = getExact(key);
                        map.put(key, distribution);
                    }
                }
                subMap = getSubMap("@", "A");
                for (String mx : subMap.keySet()) {
                    String hostKey = '.' + mx.substring(1);
                    if (hostKey.endsWith(hostname)) {
                        distribution = getExact(mx);
                        map.put(mx, distribution);
                    }
                }
            } else {
                distribution = getExact(value);
                map.put(value, distribution);
            }
            return map;
        }

        /**
         * Retorna uma distribuição binomial do whois informado.
         *
         * @param key o whois cuja distribuição deve ser retornada.
         * @return uma distribuição binomial do whois informado.
         */
        private static Distribution get(String key, boolean create) {
            Distribution distribution = getExact(key);
            if (distribution != null) {
                if (distribution.isExpired7()) {
                    distribution.reset();
                }
            } else if (create) {
                distribution = new Distribution();
                putExact(key, distribution);
            } else {
                distribution = null;
            }
            return distribution;
        }

        private static TreeMap<String,Distribution> getTreeMap() {
            TreeMap<String,Distribution> distributionMap = new TreeMap<String,Distribution>();
            distributionMap.putAll(getMap());
            return distributionMap;
        }
        
        private static TreeMap<String,Distribution> getTreeMapIPv4() {
            TreeMap<String,Distribution> distributionMap = new TreeMap<String,Distribution>();
            for (String key : keySet()) {
                if (SubnetIPv4.isValidIPv4(key)) {
                    Distribution distribution = getExact(key);
                    if (distribution != null) {
                        distributionMap.put(key, distribution);
                    }
                }
            }
            return distributionMap;
        }
        
        private static TreeMap<String,Distribution> getTreeMapIPv6() {
            TreeMap<String,Distribution> distributionMap = new TreeMap<String,Distribution>();
            for (String key : keySet()) {
                if (SubnetIPv6.isValidIPv6(key)) {
                    Distribution distribution = getExact(key);
                    if (distribution != null) {
                        distributionMap.put(key, distribution);
                    }
                }
            }
            return distributionMap;
        }

        private static TreeMap<String,Distribution> getMap(TreeSet<String> tokenSet) {
            TreeMap<String, Distribution> distributionMap = new TreeMap<String,Distribution>();
            for (String token : tokenSet) {
                Distribution distribution = getExact(token);
                if (distribution != null) {
                    distributionMap.put(token, distribution);
                }
            }
            return distributionMap;
        }
    }
    
    public static void dropExpiredDistribution() {
        CacheDistribution.dropExpired();
    }
    

    public static TreeMap<String,Distribution> getDistributionMap() {
        return CacheDistribution.getTreeMap();
    }
    
    public static TreeMap<String,Distribution> getDistributionMapIPv4() {
        return CacheDistribution.getTreeMapIPv4();
    }
    
    public static TreeMap<String,Distribution> getDistributionMapIPv6() {
        return CacheDistribution.getTreeMapIPv6();
    }

    public static void dropDistribution(String token) {
        CacheDistribution.drop(token);
    }

    /**
     * Classe que representa o cache de provedores de e-mail.
     */
    private static class CacheProvider {

        /**
         * Conjunto de provedores notórios de e-mail.
         */
        private static final TreeSet<String> SET = new TreeSet<String>();
        /**
         * Flag que indica se o cache foi modificado.
         */
        private static boolean CHANGED = false;

        private static boolean dropExact(String token) {
            if (SET.remove(token)) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }

        private static boolean addExact(String token) {
            if (SET.add(token)) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }
        
        private static synchronized TreeSet<String> getAll() throws ProcessException {
            TreeSet<String> blockSet = new TreeSet<String>();
            blockSet.addAll(SET);
            return blockSet;
        }

        private static boolean containsExact(String address) {
            return SET.contains(address);
        }

        private static synchronized Set<String> subSet(String begin, String end) {
            return SET.subSet(begin, false, end, false);
        }
        
        private static boolean add(String address) throws ProcessException {
            if ((address = normalizeProvider(address)) == null) {
                throw new ProcessException("ERROR: PROVIDER INVALID");
            } else if (addExact(address)) {
                return true;
            } else {
                return false;
            }
        }
        
        private static TreeSet<String> dropAll() throws ProcessException {
            TreeSet<String> blockSet = new TreeSet<String>();
            for (String token : getAll()) {
                if (dropExact(token)) {
                    blockSet.add(token);
                }
            }
            return blockSet;
        }

        private static boolean drop(String address) throws ProcessException {
            if ((address = normalizeProvider(address)) == null) {
                throw new ProcessException("ERROR: PROVIDER INVALID");
            } else if (dropExact(address)) {
                return true;
            } else {
                return false;
            }
        }

        private static boolean containsHELO(String ip, String helo) {
            if (CacheHELO.match(ip, helo)) {
                helo = Domain.extractHost(helo, true);
                do {
                    int index = helo.indexOf('.') + 1;
                    helo = helo.substring(index);
                    if (SET.contains('.' + helo)) {
                        return true;
                    }
                } while (helo.contains("."));
            }
            // Verifica o CIDR.
            for (String cidr : subSet("CIDR=", "CIDR>")) {
                int index = cidr.indexOf('=');
                cidr = cidr.substring(index + 1);
                if (Subnet.containsIP(cidr, ip)) {
                    return true;
                }
            }
            return false;
        }

        private static void store() {
            if (CHANGED) {
                try {
                    long time = System.currentTimeMillis();
                    File file = new File("./data/provider.set");
                    TreeSet<String> set = getAll();
                    FileOutputStream outputStream = new FileOutputStream(file);
                    try {
                        SerializationUtils.serialize(set, outputStream);
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

        private static void load() {
            long time = System.currentTimeMillis();
            File file = new File("./data/provider.set");
            if (file.exists()) {
                try {
                    TreeSet<String> set;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        set = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    for (String token : set) {
                        addExact(token);
                    }
                    CHANGED = false;
                    Server.logLoad(time, file);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }
    }

    public static boolean addProvider(String provider) throws ProcessException {
        return CacheProvider.add(provider);
    }
    
    public static TreeSet<String> dropAllProvider() throws ProcessException {
        return CacheProvider.dropAll();
    }

    public static boolean dropProvider(String provider) throws ProcessException {
        return CacheProvider.drop(provider);
    }

    /**
     * Classe que representa o cache de whitelist.
     */
    private static class CacheWhite {

        /**
         * Conjunto de remetentes em whitelist.
         */
        private static final TreeSet<String> SET = new TreeSet<String>();
        /**
         * Flag que indica se o cache foi modificado.
         */
        private static boolean CHANGED = false;
        
        private static boolean dropExact(String token) {
            if (SET.remove(token)) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }

        private static boolean addExact(String token) {
            if (SET.add(token)) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }
        
        private static synchronized TreeSet<String> getAll() throws ProcessException {
            TreeSet<String> blockSet = new TreeSet<String>();
            blockSet.addAll(SET);
            return blockSet;
        }

        private static boolean containsExact(String address) {
            return SET.contains(address);
        }

        private static synchronized Set<String> subSet(String begin, String end) {
            return SET.subSet(begin, false, end, false);
        }
        
        private static boolean add(
                String sender) throws ProcessException {
            if ((sender = normalizeTokenWhite(sender)) == null) {
                throw new ProcessException("ERROR: SENDER INVALID");
            } else if (addExact(sender)) {
                return true;
            } else {
                return false;
            }
        }

        private static boolean add(
                String client, String sender) throws ProcessException {
            if (client == null) {
                throw new ProcessException("ERROR: CLIENT INVALID");
            } else if ((sender = normalizeTokenWhite(sender)) == null) {
                throw new ProcessException("ERROR: SENDER INVALID");
            } else if (addExact(client + ':' + sender)) {
                return true;
            } else {
                return false;
            }
        }
        
        private static TreeSet<String> dropAll() throws ProcessException {
            TreeSet<String> whiteSet = new TreeSet<String>();
            for (String white : getAll()) {
                if (dropExact(white)) {
                    whiteSet.add(white);
                }
            }
            return whiteSet;
        }

        private static boolean drop(
                String sender) throws ProcessException {
            if ((sender = normalizeTokenWhite(sender)) == null) {
                throw new ProcessException("ERROR: SENDER INVALID");
            } else if (dropExact(sender)) {
                return true;
            } else {
                return false;
            }
        }

        private static boolean drop(String client,
                String sender) throws ProcessException {
            if (client == null) {
                throw new ProcessException("ERROR: CLIENT INVALID");
            } else if ((sender = normalizeTokenWhite(sender)) == null) {
                throw new ProcessException("ERROR: SENDER INVALID");
            } else if (dropExact(client + ':' + sender)) {
                return true;
            } else {
                return false;
            }
        }

        private static TreeSet<String> get(
                String client) throws ProcessException {
            TreeSet<String> whiteSet = new TreeSet<String>();
            for (String sender : getAll()) {
                if (sender.startsWith(client + ':')) {
                    int index = sender.indexOf(':') + 1;
                    sender = sender.substring(index);
                    whiteSet.add(sender);
                }
            }
            return whiteSet;
        }
        
        private static TreeSet<String> getAll(
                String client) throws ProcessException {
            TreeSet<String> whiteSet = new TreeSet<String>();
            for (String sender : getAll()) {
                if (!sender.contains(":")) {
                    whiteSet.add(sender);
                } else if (sender.startsWith(client + ':')) {
                    int index = sender.indexOf(':') + 1;
                    sender = sender.substring(index);
                    whiteSet.add(sender);
                }
            }
            return whiteSet;
        }
        
        private static TreeSet<String> get() throws ProcessException {
            TreeSet<String> whiteSet = new TreeSet<String>();
            for (String sender : getAll()) {
                if (!sender.contains(":")) {
                    whiteSet.add(sender);
                }
            }
            return whiteSet;
        }
        
        private static boolean containsSender(String client,
                String sender, String qualifier,
                String recipient) throws ProcessException {
            // Definição do destinatário.
            String recipientDomain;
            if (recipient != null && recipient.contains("@")) {
                int index = recipient.indexOf('@');
                recipient = recipient.toLowerCase();
                recipientDomain = recipient.substring(index);
            } else {
                recipient = null;
                recipientDomain = null;
            }
            // Verifica o remetente.
            if (sender != null && sender.contains("@")) {
                sender = sender.toLowerCase();
                int index1 = sender.indexOf('@');
                int index2 = sender.lastIndexOf('@');
                String part = sender.substring(0, index1 + 1);
                String senderDomain = sender.substring(index2);
                if (containsExact(sender)) {
                    return true;
                } else if (containsExact(sender + ';' + qualifier + '>' + recipient)) {
                    return true;
                } else if (containsExact(sender + ';' + qualifier + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(sender + ';' + qualifier)) {
                    return true;
                } else if (containsExact(sender + ';' + qualifier + '>' + recipient)) {
                    return true;
                } else if (containsExact(sender + ';' + qualifier + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(client + ':' + sender)) {
                    return true;
                } else if (containsExact(client + ':' + sender + '>' + recipient)) {
                    return true;
                } else if (containsExact(client + ':' + sender + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(client + ':' + sender + ';' + qualifier)) {
                    return true;
                } else if (containsExact(client + ':' + sender + ';' + qualifier + '>' + recipient)) {
                    return true;
                } else if (containsExact(client + ':' + sender + ';' + qualifier + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(part)) {
                    return true;
                } else if (containsExact(part + '>' + recipient)) {
                    return true;
                } else if (containsExact(part + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(part + ';' + qualifier)) {
                    return true;
                } else if (containsExact(part + ';' + qualifier + '>' + recipient)) {
                    return true;
                } else if (containsExact(part + ';' + qualifier + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(client + ':' + part)) {
                    return true;
                } else if (containsExact(client + ':' + part + '>' + recipient)) {
                    return true;
                } else if (containsExact(client + ':' + part + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(client + ':' + part + ';' + qualifier)) {
                    return true;
                } else if (containsExact(client + ':' + part + ';' + qualifier + '>' + recipient)) {
                    return true;
                } else if (containsExact(client + ':' + part + ';' + qualifier + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(senderDomain)) {
                    return true;
                } else if (containsExact(senderDomain + '>' + recipient)) {
                    return true;
                } else if (containsExact(senderDomain + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(senderDomain + ';' + qualifier)) {
                    return true;
                } else if (containsExact(senderDomain + ';' + qualifier + '>' + recipient)) {
                    return true;
                } else if (containsExact(senderDomain + ';' + qualifier + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(client + ':' + senderDomain)) {
                    return true;
                } else if (containsExact(client + ':' + senderDomain + '>' + recipient)) {
                    return true;
                } else if (containsExact(client + ':' + senderDomain + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(client + ':' + senderDomain + ';' + qualifier)) {
                    return true;
                } else if (containsExact(client + ':' + senderDomain + ';' + qualifier + '>' + recipient)) {
                    return true;
                } else if (containsExact(client + ':' + senderDomain + ';' + qualifier + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact("@;" + qualifier +  ">" + recipient)) {
                    return true;
                } else if (containsExact("@;" + qualifier +  ">" + recipientDomain)) {
                    return true;
                } else if (containsExact(client + ":@>" + recipient)) {
                    return true;
                } else if (containsExact(client + ":@>" + recipientDomain)) {
                    return true;
                } else if (containsHost(client, senderDomain.substring(1), qualifier, recipient, recipientDomain)) {
                    return true;
                } else {
                    int index3 = senderDomain.length();
                    while ((index3 = senderDomain.lastIndexOf('.', index3 - 1)) > index2) {
                        String subdomain = senderDomain.substring(0, index3 + 1);
                        if (containsExact(subdomain)) {
                            return true;
                        } else if (containsExact(subdomain + '>' + recipient)) {
                            return true;
                        } else if (containsExact(subdomain + '>' + recipientDomain)) {
                            return true;
                        } else if (containsExact(subdomain + ';' + qualifier)) {
                            return true;
                        } else if (containsExact(subdomain + ';' + qualifier + '>' + recipient)) {
                            return true;
                        } else if (containsExact(subdomain + ';' + qualifier + '>' + recipientDomain)) {
                            return true;
                        } else if (containsExact(client + ':' + subdomain)) {
                            return true;
                        } else if (containsExact(client + ':' + subdomain + '>' + recipient)) {
                            return true;
                        } else if (containsExact(client + ':' + subdomain + '>' + recipientDomain)) {
                            return true;
                        } else if (containsExact(client + ':' + subdomain + ';' + qualifier)) {
                            return true;
                        } else if (containsExact(client + ':' + subdomain + ';' + qualifier + '>' + recipient)) {
                            return true;
                        } else if (containsExact(client + ':' + subdomain + ';' + qualifier + '>' + recipientDomain)) {
                            return true;
                        }
                    }
                    int index4 = sender.length();
                    while ((index4 = sender.lastIndexOf('.', index4 - 1)) > index2) {
                        String subsender = sender.substring(0, index4 + 1);
                        if (containsExact(subsender)) {
                            return true;
                        } else if (containsExact(subsender + '>' + recipient)) {
                            return true;
                        } else if (containsExact(subsender + '>' + recipientDomain)) {
                            return true;
                        } else if (containsExact(subsender + ';' + qualifier)) {
                            return true;
                        } else if (containsExact(subsender + ';' + qualifier + '>' + recipient)) {
                            return true;
                        } else if (containsExact(subsender + ';' + qualifier + '>' + recipientDomain)) {
                            return true;
                        } else if (containsExact(client + ':' + subsender)) {
                            return true;
                        } else if (containsExact(client + ':' + subsender + '>' + recipient)) {
                            return true;
                        } else if (containsExact(client + ':' + subsender + '>' + recipientDomain)) {
                            return true;
                        } else if (containsExact(client + ':' + subsender + ';' + qualifier)) {
                            return true;
                        } else if (containsExact(client + ':' + subsender + ';' + qualifier + '>' + recipient)) {
                            return true;
                        } else if (containsExact(client + ':' + subsender + ';' + qualifier + '>' + recipientDomain)) {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        private static boolean contains(String client,
                String ip, String sender, String helo,
                String qualifier, String recipient) {
            TreeSet<String> whoisSet = new TreeSet<String>();
            TreeSet<String> regexSet = new TreeSet<String>();
            // Definição do destinatário.
            String recipientDomain;
            if (recipient != null && recipient.contains("@")) {
                int index = recipient.indexOf('@');
                recipient = recipient.toLowerCase();
                recipientDomain = recipient.substring(index);
            } else {
                recipient = null;
                recipientDomain = null;
            }
            // Verifica o remetente.
            if (sender != null && sender.contains("@")) {
                sender = sender.toLowerCase();
                int index1 = sender.indexOf('@');
                int index2 = sender.lastIndexOf('@');
                String part = sender.substring(0, index1 + 1);
                String senderDomain = sender.substring(index2);
                if (containsExact(sender)) {
                    return true;
                } else if (containsExact(sender + ';' + qualifier + '>' + recipient)) {
                    return true;
                } else if (containsExact(sender + ';' + qualifier + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(sender + ';' + qualifier)) {
                    return true;
                } else if (containsExact(sender + ';' + qualifier + '>' + recipient)) {
                    return true;
                } else if (containsExact(sender + ';' + qualifier + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(client + ':' + sender)) {
                    return true;
                } else if (containsExact(client + ':' + sender + '>' + recipient)) {
                    return true;
                } else if (containsExact(client + ':' + sender + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(client + ':' + sender + ';' + qualifier)) {
                    return true;
                } else if (containsExact(client + ':' + sender + ';' + qualifier + '>' + recipient)) {
                    return true;
                } else if (containsExact(client + ':' + sender + ';' + qualifier + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(part)) {
                    return true;
                } else if (containsExact(part + '>' + recipient)) {
                    return true;
                } else if (containsExact(part + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(part + ';' + qualifier)) {
                    return true;
                } else if (containsExact(part + ';' + qualifier + '>' + recipient)) {
                    return true;
                } else if (containsExact(part + ';' + qualifier + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(client + ':' + part)) {
                    return true;
                } else if (containsExact(client + ':' + part + '>' + recipient)) {
                    return true;
                } else if (containsExact(client + ':' + part + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(client + ':' + part + ';' + qualifier)) {
                    return true;
                } else if (containsExact(client + ':' + part + ';' + qualifier + '>' + recipient)) {
                    return true;
                } else if (containsExact(client + ':' + part + ';' + qualifier + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(senderDomain)) {
                    return true;
                } else if (containsExact(senderDomain + '>' + recipient)) {
                    return true;
                } else if (containsExact(senderDomain + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(senderDomain + ';' + qualifier)) {
                    return true;
                } else if (containsExact(senderDomain + ';' + qualifier + '>' + recipient)) {
                    return true;
                } else if (containsExact(senderDomain + ';' + qualifier + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(client + ':' + senderDomain)) {
                    return true;
                } else if (containsExact(client + ':' + senderDomain + '>' + recipient)) {
                    return true;
                } else if (containsExact(client + ':' + senderDomain + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(client + ':' + senderDomain + ';' + qualifier)) {
                    return true;
                } else if (containsExact(client + ':' + senderDomain + ';' + qualifier + '>' + recipient)) {
                    return true;
                } else if (containsExact(client + ':' + senderDomain + ';' + qualifier + '>' + recipientDomain)) {
                    return true;
                } else if (containsHost(client, senderDomain.substring(1), qualifier, recipient, recipientDomain)) {
                    return true;
                } else if (containsExact("@;" + qualifier +  ">" + recipient)) {
                    return true;
                } else if (containsExact("@;" + qualifier +  ">" + recipientDomain)) {
                    return true;
                } else if (containsExact(client + ":@>" + recipient)) {
                    return true;
                } else if (containsExact(client + ":@>" + recipientDomain)) {
                    return true;
                } else {
                    int index3 = senderDomain.length();
                    while ((index3 = senderDomain.lastIndexOf('.', index3 - 1)) > index2) {
                        String subdomain = senderDomain.substring(0, index3 + 1);
                        if (containsExact(subdomain)) {
                            return true;
                        } else if (containsExact(subdomain + '>' + recipient)) {
                            return true;
                        } else if (containsExact(subdomain + '>' + recipientDomain)) {
                            return true;
                        } else if (containsExact(subdomain + ';' + qualifier)) {
                            return true;
                        } else if (containsExact(subdomain + ';' + qualifier + '>' + recipient)) {
                            return true;
                        } else if (containsExact(subdomain + ';' + qualifier + '>' + recipientDomain)) {
                            return true;
                        } else if (containsExact(client + ':' + subdomain)) {
                            return true;
                        } else if (containsExact(client + ':' + subdomain + '>' + recipient)) {
                            return true;
                        } else if (containsExact(client + ':' + subdomain + '>' + recipientDomain)) {
                            return true;
                        } else if (containsExact(client + ':' + subdomain + ';' + qualifier)) {
                            return true;
                        } else if (containsExact(client + ':' + subdomain + ';' + qualifier + '>' + recipient)) {
                            return true;
                        } else if (containsExact(client + ':' + subdomain + ';' + qualifier + '>' + recipientDomain)) {
                            return true;
                        }
                    }
                    int index4 = sender.length();
                    while ((index4 = sender.lastIndexOf('.', index4 - 1)) > index2) {
                        String subsender = sender.substring(0, index4 + 1);
                        if (containsExact(subsender)) {
                            return true;
                        } else if (containsExact(subsender + '>' + recipient)) {
                            return true;
                        } else if (containsExact(subsender + '>' + recipientDomain)) {
                            return true;
                        } else if (containsExact(subsender + ';' + qualifier)) {
                            return true;
                        } else if (containsExact(subsender + ';' + qualifier + '>' + recipient)) {
                            return true;
                        } else if (containsExact(subsender + ';' + qualifier + '>' + recipientDomain)) {
                            return true;
                        } else if (containsExact(client + ':' + subsender)) {
                            return true;
                        } else if (containsExact(client + ':' + subsender + '>' + recipient)) {
                            return true;
                        } else if (containsExact(client + ':' + subsender + '>' + recipientDomain)) {
                            return true;
                        } else if (containsExact(client + ':' + subsender + ';' + qualifier)) {
                            return true;
                        } else if (containsExact(client + ':' + subsender + ';' + qualifier + '>' + recipient)) {
                            return true;
                        } else if (containsExact(client + ':' + subsender + ';' + qualifier + '>' + recipientDomain)) {
                            return true;
                        }
                    }
                }
                if (senderDomain.endsWith(".br")) {
                    whoisSet.add(senderDomain);
                }
                regexSet.add(sender);
            }
            // Verifica o HELO.
            if ((helo = Domain.extractHost(helo, true)) != null) {
                if (containsHost(client, helo, qualifier, recipient, recipientDomain)) {
                    return true;
                }
                if (helo.endsWith(".br") && CacheHELO.match(ip, helo)) {
                    whoisSet.add(helo);
                }
                regexSet.add(helo);
            }
            // Verifica o IP.
            if (ip != null) {
                ip = Subnet.normalizeIP(ip);
                if (containsExact(ip)) {
                    return true;
                } else if (containsExact(ip + '>' + recipient)) {
                    return true;
                } else if (containsExact(ip + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(ip + ';' + qualifier)) {
                    return true;
                } else if (containsExact(ip + ';' + qualifier + '>' + recipient)) {
                    return true;
                } else if (containsExact(ip + ';' + qualifier + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(client + ':' + ip)) {
                    return true;
                } else if (containsExact(client + ':' + ip + '>' + recipient)) {
                    return true;
                } else if (containsExact(client + ':' + ip + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(client + ':' + ip + ';' + qualifier)) {
                    return true;
                } else if (containsExact(client + ':' + ip + ';' + qualifier + '>' + recipient)) {
                    return true;
                } else if (containsExact(client + ':' + ip + ';' + qualifier + '>' + recipientDomain)) {
                    return true;
                }
                whoisSet.add(ip);
                regexSet.add(ip);
            }
            // Verifica o CIDR.
            if (ip != null) {
                for (String cidr : subSet("CIDR=", "CIDR>")) {
                    int index = cidr.indexOf('=');
                    cidr = cidr.substring(index + 1);
                    if (Subnet.containsIP(cidr, ip)) {
                        return true;
                    }
                }
                for (String cidr : subSet(client + ":CIDR=", client + ":CIDR>")) {
                    int index = cidr.indexOf('=');
                    cidr = cidr.substring(index + 1);
                    if (Subnet.containsIP(cidr, ip)) {
                        return true;
                    }
                }
            }
            // Verifica um critério do REGEX.
            if (!regexSet.isEmpty()) {
                for (String whois : subSet("REGEX=", "REGEX>")) {
                    int index = whois.indexOf('=');
                    String regex = whois.substring(index + 1);
                    for (String token : regexSet) {
                        if (matches(regex, token)) {
                            return true;
                        }
                    }
                }
                for (String whois : subSet(client + ":REGEX=", client + ":REGEX>")) {
                    int index = whois.indexOf('=');
                    String regex = whois.substring(index + 1);
                    for (String token : regexSet) {
                        if (matches(regex, token)) {
                            return true;
                        }
                    }
                }
            }
            // Verifica critérios do WHOIS.
            if (!whoisSet.isEmpty()) {
                for (String whois : subSet("WHOIS/", "WHOIS<")) {
                    int indexKey = whois.indexOf('/');
                    int indexValue = whois.indexOf('=');
                    String key = whois.substring(indexKey + 1, indexValue);
                    String criterion = whois.substring(indexValue + 1);
                    for (String token : whoisSet) {
                        String value;
                        if (Subnet.isValidIP(token)) {
                            value = Subnet.getValue(token, key);
                        } else if (Domain.containsDomain(token)) {
                            value = Domain.getValue(token, key);
                        } else {
                            value = "";
                        }
                        if (criterion.equals(value)) {
                            return true;
                        }
                    }
                }
                for (String whois : subSet(client + ":WHOIS/", client + ":WHOIS<")) {
                    int indexKey = whois.indexOf('/');
                    int indexValue = whois.indexOf('=');
                    String key = whois.substring(indexKey + 1, indexValue);
                    String criterion = whois.substring(indexValue + 1);
                    for (String token : whoisSet) {
                        String value;
                        if (Subnet.isValidIP(token)) {
                            value = Subnet.getValue(token, key);
                        } else if (Domain.containsDomain(token)) {
                            value = Domain.getValue(token, key);
                        } else {
                            value = "";
                        }
                        if (criterion.equals(value)) {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        private static boolean containsHost(String client,
                String host, String qualifier,
                String recipient, String recipientDomain) {
            do {
                int index = host.indexOf('.') + 1;
                host = host.substring(index);
                String token = '.' + host;
                if (containsExact(token)) {
                    return true;
                } else if (containsExact(token + '>' + recipient)) {
                    return true;
                } else if (containsExact(token + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(token + ';' + qualifier)) {
                    return true;
                } else if (containsExact(token + ';' + qualifier + '>' + recipient)) {
                    return true;
                } else if (containsExact(token + ';' + qualifier + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(client + ':' + token)) {
                    return true;
                } else if (containsExact(client + ':' + token + '>' + recipient)) {
                    return true;
                } else if (containsExact(client + ':' + token + '>' + recipientDomain)) {
                    return true;
                } else if (containsExact(client + ':' + token + ';' + qualifier)) {
                    return true;
                } else if (containsExact(client + ':' + token + ';' + qualifier + '>' + recipient)) {
                    return true;
                } else if (containsExact(client + ':' + token + ';' + qualifier + '>' + recipientDomain)) {
                    return true;
                }
            } while (host.contains("."));
            return false;
        }

        private static void store() {
            if (CHANGED) {
                try {
                    long time = System.currentTimeMillis();
                    File file = new File("./data/white.set");
                    TreeSet<String> set = getAll();
                    FileOutputStream outputStream = new FileOutputStream(file);
                    try {
                        SerializationUtils.serialize(set, outputStream);
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

        private static void load() {
            long time = System.currentTimeMillis();
            File file = new File("./data/white.set");
            if (file.exists()) {
                try {
                    Set<String> set;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        set = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    // Processo temporário de transição.
                    for (String token : set) {
                        String client;
                        String identifier;
                        if (token.contains(":")) {
                            int index = token.indexOf(':');
                            client = token.substring(0, index);
                            identifier = token.substring(index + 1);
                        } else {
                            client = null;
                            identifier = token;
                        }
                        if (Subnet.isValidCIDR(identifier)) {
                            identifier = "CIDR=" + Subnet.normalizeCIDR(identifier);
                        } else if (Owner.isOwnerID(identifier)) {
                            identifier = "WHOIS/ownerid=" + identifier;
                        }
                        if (client == null) {
                            addExact(identifier);
                        } else {
                            addExact(client + ':' + identifier);
                        }
                    }
                    CHANGED = false;
                    Server.logLoad(time, file);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }
    }

    public static boolean addWhite(String sender) throws ProcessException {
        return CacheWhite.add(sender);
    }

    public static boolean addWhite(String client, String sender) throws ProcessException {
        return CacheWhite.add(client, sender);
    }

    public static TreeSet<String> dropAllWhite() throws ProcessException {
        return CacheWhite.dropAll();
    }
    
    public static boolean dropWhite(String sender) throws ProcessException {
        return CacheWhite.drop(sender);
    }

    public static boolean dropWhite(String client, String sender) throws ProcessException {
        return CacheWhite.drop(client, sender);
    }

    public static TreeSet<String> getWhiteSet(String client) throws ProcessException {
        return CacheWhite.get(client);
    }
    
    public static TreeSet<String> getAllWhiteSet(String client) throws ProcessException {
        return CacheWhite.getAll(client);
    }
    
    public static TreeSet<String> getWhiteSet() throws ProcessException {
        return CacheWhite.get();
    }
    
    public static TreeSet<String> getAllWhiteSet() throws ProcessException {
        return CacheWhite.getAll();
    }

    /**
     * Classe que representa o cache de spamtrap.
     */
    private static class CacheTrap {

        /**
         * Conjunto de destinatarios de spamtrap.
         */
        private static final HashSet<String> SET = new HashSet<String>();
        /**
         * Flag que indica se o cache foi modificado.
         */
        private static boolean CHANGED = false;
        
        private static boolean dropExact(String token) {
            if (SET.remove(token)) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }

        private static boolean addExact(String token) {
            if (SET.add(token)) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }
        
        private static synchronized TreeSet<String> getAll() throws ProcessException {
            TreeSet<String> blockSet = new TreeSet<String>();
            blockSet.addAll(SET);
            return blockSet;
        }

        private static boolean containsExact(String address) {
            return SET.contains(address);
        }

        private static boolean isValid(String recipient) {
            if (recipient == null) {
                return false;
            } else if (Domain.isEmail(recipient)) {
                return true;
            } else if (recipient.startsWith("@") && Domain.containsDomain(recipient.substring(1))) {
                return true;
            } else {
                return false;
            }
        }

        private static boolean add(String recipient) throws ProcessException {
            if (!isValid(recipient)) {
                throw new ProcessException("ERROR: RECIPIENT INVALID");
            } else if (addExact(recipient.toLowerCase())) {
                return true;
            } else {
                return false;
            }
        }

        private static boolean add(String client, String recipient) throws ProcessException {
            if (client == null) {
                throw new ProcessException("ERROR: CLIENT INVALID");
            } else if (!isValid(recipient)) {
                throw new ProcessException("ERROR: RECIPIENT INVALID");
            } else if (addExact(client + ':' + recipient.toLowerCase())) {
                return true;
            } else {
                return false;
            }
        }
        
        private static TreeSet<String> dropAll() throws ProcessException {
            TreeSet<String> trapSet = new TreeSet<String>();
            for (String trap : getAll()) {
                if (dropExact(trap)) {
                    trapSet.add(trap);
                }
            }
            return trapSet;
        }

        private static boolean drop(String recipient) throws ProcessException {
            if (!isValid(recipient)) {
                throw new ProcessException("ERROR: RECIPIENT INVALID");
            } else if (dropExact(recipient.toLowerCase())) {
                return true;
            } else {
                return false;
            }
        }

        private static boolean drop(String client, String recipient) throws ProcessException {
            if (client == null) {
                throw new ProcessException("ERROR: CLIENT INVALID");
            } else if (!isValid(recipient)) {
                throw new ProcessException("ERROR: RECIPIENT INVALID");
            } else if (dropExact(client + ':' + recipient.toLowerCase())) {
                return true;
            } else {
                return false;
            }
        }

        private static TreeSet<String> get(String client) throws ProcessException {
            TreeSet<String> trapSet = new TreeSet<String>();
            for (String recipient : getAll()) {
                if (recipient.startsWith(client + ':')) {
                    int index = recipient.indexOf(':') + 1;
                    recipient = recipient.substring(index);
                    trapSet.add(recipient);
                }
            }
            return trapSet;
        }
        
        private static TreeSet<String> get() throws ProcessException {
            TreeSet<String> trapSet = new TreeSet<String>();
            for (String recipient : getAll()) {
                if (!recipient.contains(":")) {
                    trapSet.add(recipient);
                }
            }
            return trapSet;
        }

        private static boolean contains(String client, String recipient) {
            if (client == null) {
                return false;
            } else if (!isValid(recipient)) {
                return false;
            } else {
                recipient = recipient.toLowerCase();
                int index2 = recipient.lastIndexOf('@');
                String domain = recipient.substring(recipient.lastIndexOf('@'));
                if (containsExact(recipient)) {
                    return true;
                } else if (containsExact(domain)) {
                    return true;
                } else if (containsExact(client + ':' + recipient)) {
                    return true;
                } else if (containsExact(client + ':' + domain)) {
                    return true;
                } else {
                    int index3 = domain.length();
                    while ((index3 = domain.lastIndexOf('.', index3 - 1)) > index2) {
                        String subdomain = domain.substring(0, index3 + 1);
                        if (containsExact(subdomain)) {
                            return true;
                        } else if (containsExact(client + ':' + subdomain)) {
                            return true;
                        }
                    }
                    int index4 = recipient.length();
                    while ((index4 = recipient.lastIndexOf('.', index4 - 1)) > index2) {
                        String subrecipient = recipient.substring(0, index4 + 1);
                        if (containsExact(subrecipient)) {
                            return true;
                        } else if (containsExact(client + ':' + subrecipient)) {
                            return true;
                        }
                    }
                    return false;
                }
            }
        }

        private static void store() {
            if (CHANGED) {
                try {
                    long time = System.currentTimeMillis();
                    File file = new File("./data/trap.set");
                    TreeSet<String> set = getAll();
                    FileOutputStream outputStream = new FileOutputStream(file);
                    try {
                        SerializationUtils.serialize(set, outputStream);
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

        private static void load() {
            long time = System.currentTimeMillis();
            File file = new File("./data/trap.set");
            if (file.exists()) {
                try {
                    Set<String> set;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        set = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    for (String token : set) {
                        addExact(token);
                    }
                    CHANGED = false;
                    Server.logLoad(time, file);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }
    }

    public static boolean addTrap(String sender) throws ProcessException {
        return CacheTrap.add(sender);
    }

    public static boolean addTrap(String client, String sender) throws ProcessException {
        return CacheTrap.add(client, sender);
    }
    
    public static TreeSet<String> dropAllTrap() throws ProcessException {
        return CacheTrap.dropAll();
    }

    public static boolean dropTrap(String sender) throws ProcessException {
        return CacheTrap.drop(sender);
    }

    public static boolean dropTrap(String client, String sender) throws ProcessException {
        return CacheTrap.drop(client, sender);
    }

    public static TreeSet<String> getTrapSet() throws ProcessException {
        return CacheTrap.get();
    }
    
    public static TreeSet<String> getTrapSet(String client) throws ProcessException {
        return CacheTrap.get(client);
    }
    
    public static TreeSet<String> getAllTrapSet() throws ProcessException {
        return CacheTrap.getAll();
    }

    private static boolean matches(String regex, String token) {
        try {
            return Pattern.matches(regex, token);
        } catch (Exception ex) {
            return false;
        }
    }

    private static boolean isWHOIS(String token) {
        return matches("^WHOIS(/[a-z-]+)+((=[a-zA-Z0-9@/.-]+)|((<|>)[0-9]+))$", token);
    }

    private static boolean isREGEX(String token) {
        return matches("^REGEX=[^ ]+$", token);
    }

    private static boolean isCIDR(String token) {
        return matches("^CIDR=("
                + "((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}"
                + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])/[0-9]{1,2})"
                + "|"
                + "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
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
                + "(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])/[0-9]{1,3})"
                + ")$", token);
    }

    private static String normalizeCIDR(String token) {
        if (token == null) {
            return null;
        } else if (token.startsWith("CIDR=")) {
            int index = token.indexOf('=');
            String cidr = token.substring(index + 1);
            return "CIDR=" + Subnet.normalizeCIDR(cidr);
        } else {
            return null;
        }
    }

    private static String normalizeToken(String token) throws ProcessException {
        return normalizeToken(token, true, true, true, false);
    }
    
    private static String normalizeProvider(String token) throws ProcessException {
        return normalizeToken(token, false, false, true, false);
    }
    
    private static String normalizeTokenWhite(String token) throws ProcessException {
        return normalizeToken(token, true, true, true, true);
    }

    private static String normalizeTokenCIDR(String token) throws ProcessException {
        return normalizeToken(token, false, false, true, false);
    }

    private static String normalizeToken(
            String token,
            boolean canWhois,
            boolean canRegex,
            boolean canCidr,
            boolean canFail
            ) throws ProcessException {
        if (token == null || token.length() == 0) {
            return null;
        } else if (canWhois && isWHOIS(token)) {
            return token;
        } else if (canRegex && isREGEX(token)) {
            try {
                int index = token.indexOf('=');
                String regex = token.substring(index + 1);
                Pattern.compile(regex);
                return token;
            } catch (Exception ex) {
                return null;
            }
        } else if (canCidr && isCIDR(token)) {
            return normalizeCIDR(token);
        } else if (canWhois && Owner.isOwnerID(token)) {
            return "WHOIS/ownerid=" + Owner.normalizeID(token);
        } else if (canCidr && Subnet.isValidCIDR(token)) {
            return "CIDR=" + Subnet.normalizeCIDR(token);
        } else {
            token = Core.removerAcentuacao(token);
            String recipient = "";
            if (token.contains(">")) {
                int index = token.indexOf('>');
                recipient = token.substring(index + 1);
                token = token.substring(0, index);
                if (Domain.isEmail(recipient)) {
                    recipient = '>' + recipient.toLowerCase();
                } else if (recipient.startsWith("@") && Domain.containsDomain(recipient.substring(1))) {
                    recipient = '>' + recipient.toLowerCase();
                } else {
                    return null;
                }
            }
            String qualif = "";
            if (token.contains(";")) {
                int index = token.indexOf(';');
                qualif = token.substring(index);
                if (qualif.equals(";PASS")) {
                    token = token.substring(0, index);
                } else if (qualif.equals(";SOFTFAIL")) {
                    token = token.substring(0, index);
                } else if (qualif.equals(";NEUTRAL")) {
                    token = token.substring(0, index);
                } else if (qualif.equals(";NONE")) {
                    token = token.substring(0, index);
                } else if (canFail && qualif.equals(";FAIL")) {
                    token = token.substring(0, index);
                } else {
                    // Sintaxe com erro.
                    return null;
                }
            }
            if (Domain.isEmail(token)) {
                return token.toLowerCase() + qualif + recipient;
            } else if (token.endsWith("@")) {
                return token.toLowerCase() + qualif + recipient;
            } else if (token.startsWith("@") && Domain.containsDomain(token.substring(1))) {
                return token.toLowerCase() + qualif + recipient;
            } else if (!token.contains("@") && Domain.containsDomain(token)) {
                return Domain.extractHost(token, true) + qualif + recipient;
            } else if (token.startsWith(".") && Domain.containsDomain(token.substring(1))) {
                return Domain.extractHost(token, true) + qualif + recipient;
            } else if (Subnet.isValidIP(token)) {
                return Subnet.normalizeIP(token) + qualif + recipient;
            } else {
                return null;
            }
        }
    }

    /**
     * Classe que representa o cache de bloqueios de remetente.
     */
    private static class CacheBlock {

        /**
         * Conjunto de remetentes bloqueados.
         */
        private static final TreeSet<String> SET = new TreeSet<String>();
        /**
         * Flag que indica se o cache foi modificado.
         */
        private static boolean CHANGED = false;
        
        private static synchronized boolean dropExact(String token) {
            if (SET.remove(token)) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }
        
        private static synchronized boolean dropAll() {
            if (SET.isEmpty()) {
                return false;
            } else {
                SET.clear();
                CHANGED = true;
                return true;
            }
        }

        private static synchronized boolean addExact(String token) {
            if (SET.add(token)) {
                Peer.releaseAll(token);
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }
        
        private static synchronized TreeSet<String> getAll() throws ProcessException {
            TreeSet<String> blockSet = new TreeSet<String>();
            blockSet.addAll(SET);
            return blockSet;
        }

        private static synchronized boolean containsExact(String address) {
            return SET.contains(address);
        }

        private static synchronized Set<String> subSet(String begin, String end) {
            return SET.subSet(begin, false, end, false);
        }
        
        private static boolean add(String token) throws ProcessException {
            if ((token = normalizeToken(token)) == null) {
                throw new ProcessException("ERROR: TOKEN INVALID");
            } else if (addExact(token)) {
                return true;
            } else {
                return false;
            }
        }

        private static boolean add(String client, String token) throws ProcessException {
            if (client == null) {
                throw new ProcessException("ERROR: CLIENT INVALID");
            } else if ((token = normalizeToken(token)) == null) {
                throw new ProcessException("ERROR: TOKEN INVALID");
            } else if (addExact(client + ':' + token)) {
                return true;
            } else {
                return false;
            }
        }

        private static boolean drop(String token) throws ProcessException {
            if ((token = normalizeToken(token)) == null) {
                throw new ProcessException("ERROR: TOKEN INVALID");
            } else if (dropExact(token)) {
                return true;
            } else {
                return false;
            }
        }

        private static boolean drop(String client, String token) throws ProcessException {
            if (client == null) {
                throw new ProcessException("ERROR: CLIENT INVALID");
            } else if ((token = normalizeToken(token)) == null) {
                throw new ProcessException("ERROR: TOKEN INVALID");
            } else if (dropExact(client + ':' + token)) {
                return true;
            } else {
                return false;
            }
        }

        private static TreeSet<String> get(String client) throws ProcessException {
            TreeSet<String> blockSet = new TreeSet<String>();
            for (String token : getAll()) {
                if (token.startsWith(client + ':')) {
                    int index = token.indexOf(':') + 1;
                    token = token.substring(index);
                    blockSet.add(token);
                }
            }
            return blockSet;
        }

        private static TreeSet<String> getAll(String client) throws ProcessException {
            TreeSet<String> blockSet = new TreeSet<String>();
            for (String token : getAll()) {
                if (!token.contains(":")) {
                    blockSet.add(token);
                } else if (token.startsWith(client + ':')) {
                    int index = token.indexOf(':') + 1;
                    token = token.substring(index);
                    blockSet.add(token);
                }
            }
            return blockSet;
        }
        
        private static TreeSet<String> getAllTokens(String value) {
            TreeSet<String> blockSet = new TreeSet<String>();
            if (Subnet.isValidIP(value)) {
                String ip = Subnet.normalizeIP(value);
                if (containsExact(ip)) {
                    blockSet.add(ip);
                }
            } else if (Subnet.isValidCIDR(value)) {
                String cidr = Subnet.normalizeCIDR(value);
                if (containsExact("CIDR=" + cidr)) {
                    blockSet.add(cidr);
                }
                for (String ip : subSet("0", ":")) {
                    if (Subnet.containsIP(cidr, ip)) {
                        blockSet.add(ip);
                    }
                }
                for (String ip : subSet("a", "g")) {
                    if (SubnetIPv6.containsIP(cidr, ip)) {
                        blockSet.add(ip);
                    }
                }
            } else if (value.startsWith(".")) {
                String hostname = value;
                for (String key : subSet(".", "/")) {
                    if (key.endsWith(hostname)) {
                        blockSet.add(key);
                    }
                }
                for (String mx : subSet("@", "A")) {
                    String hostKey = '.' + mx.substring(1);
                    if (hostKey.endsWith(hostname)) {
                        blockSet.add(hostKey);
                    }
                }
            } else if (containsExact(value)) {
                blockSet.add(value);
            }
            return blockSet;
        }

        private static TreeSet<String> get() throws ProcessException {
            TreeSet<String> blockSet = new TreeSet<String>();
            for (String token : getAll()) {
                if (!token.contains(":")) {
                    blockSet.add(token);
                }
            }
            return blockSet;
        }
        
        private static boolean contains(String client,
                String ip, String sender, String helo,
                String qualifier, String recipient) {
            return find(client, ip, sender, helo,
                    qualifier, recipient) != null;
        }

        private static String find(String client,
                String ip, String sender, String helo,
                String qualifier, String recipient) {
            TreeSet<String> whoisSet = new TreeSet<String>();
            TreeSet<String> regexSet = new TreeSet<String>();
            // Definição do destinatário.
            String recipientDomain;
            if (recipient != null && recipient.contains("@")) {
                int index = recipient.indexOf('@');
                recipient = recipient.toLowerCase();
                recipientDomain = recipient.substring(index);
            } else {
                recipient = null;
                recipientDomain = null;
            }
            // Verifica o remetente.
            if (sender != null && sender.contains("@")) {
                sender = sender.toLowerCase();
                int index1 = sender.indexOf('@');
                int index2 = sender.lastIndexOf('@');
                String part = sender.substring(0, index1 + 1);
                String senderDomain = sender.substring(index2);
                if (containsExact(sender)) {
                    return sender;
                } else if (containsExact(sender + ';' + qualifier + '>' + recipient)) {
                    return sender + ';' + qualifier + '>' + recipient;
                } else if (containsExact(sender + ';' + qualifier + '>' + recipientDomain)) {
                    return sender + ';' + qualifier + '>' + recipientDomain;
                } else if (containsExact(sender + ';' + qualifier)) {
                    return sender + ';' + qualifier;
                } else if (containsExact(sender + ';' + qualifier + '>' + recipient)) {
                    return sender + ';' + qualifier + '>' + recipient;
                } else if (containsExact(sender + ';' + qualifier + '>' + recipientDomain)) {
                    return sender + ';' + qualifier + '>' + recipientDomain;
                } else if (containsExact(client + ':' + sender)) {
                    return sender;
                } else if (containsExact(client + ':' + sender + '>' + recipient)) {
                    return sender + '>' + recipient;
                } else if (containsExact(client + ':' + sender + '>' + recipientDomain)) {
                    return sender + '>' + recipientDomain;
                } else if (containsExact(client + ':' + sender + ';' + qualifier)) {
                    return sender + ';' + qualifier;
                } else if (containsExact(client + ':' + sender + ';' + qualifier + '>' + recipient)) {
                    return sender + ';' + qualifier + '>' + recipient;
                } else if (containsExact(client + ':' + sender + ';' + qualifier + '>' + recipientDomain)) {
                    return sender + ';' + qualifier + '>' + recipientDomain;
                } else if (containsExact(part)) {
                    return part;
                } else if (containsExact(part + '>' + recipient)) {
                    return part + '>' + recipient;
                } else if (containsExact(part + '>' + recipientDomain)) {
                    return part + '>' + recipientDomain;
                } else if (containsExact(part + ';' + qualifier)) {
                    return part + ';' + qualifier;
                } else if (containsExact(part + ';' + qualifier + '>' + recipient)) {
                    return part + ';' + qualifier + '>' + recipient;
                } else if (containsExact(part + ';' + qualifier + '>' + recipientDomain)) {
                    return part + ';' + qualifier + '>' + recipientDomain;
                } else if (containsExact(client + ':' + part)) {
                    return part;
                } else if (containsExact(client + ':' + part + '>' + recipient)) {
                    return part + '>' + recipient;
                } else if (containsExact(client + ':' + part + '>' + recipientDomain)) {
                    return part + '>' + recipientDomain;
                } else if (containsExact(client + ':' + part + ';' + qualifier)) {
                    return part + ';' + qualifier;
                } else if (containsExact(client + ':' + part + ';' + qualifier + '>' + recipient)) {
                    return part + ';' + qualifier + '>' + recipient;
                } else if (containsExact(client + ':' + part + ';' + qualifier + '>' + recipientDomain)) {
                    return part + ';' + qualifier + '>' + recipientDomain;
                } else if (containsExact(senderDomain)) {
                    return senderDomain;
                } else if (containsExact(senderDomain + '>' + recipient)) {
                    return senderDomain + '>' + recipient;
                } else if (containsExact(senderDomain + '>' + recipientDomain)) {
                    return senderDomain + '>' + recipientDomain;
                } else if (containsExact(senderDomain + ';' + qualifier)) {
                    return senderDomain + ';' + qualifier;
                } else if (containsExact(senderDomain + ';' + qualifier + '>' + recipient)) {
                    return senderDomain + ';' + qualifier + '>' + recipient;
                } else if (containsExact(senderDomain + ';' + qualifier + '>' + recipientDomain)) {
                    return senderDomain + ';' + qualifier + '>' + recipientDomain;
                } else if (containsExact(client + ':' + senderDomain)) {
                    return senderDomain;
                } else if (containsExact(client + ':' + senderDomain + '>' + recipient)) {
                    return senderDomain + '>' + recipient;
                } else if (containsExact(client + ':' + senderDomain + '>' + recipientDomain)) {
                    return senderDomain + '>' + recipientDomain;
                } else if (containsExact(client + ':' + senderDomain + ';' + qualifier)) {
                    return senderDomain + ';' + qualifier;
                } else if (containsExact(client + ':' + senderDomain + ';' + qualifier + '>' + recipient)) {
                    return  senderDomain + ';' + qualifier + '>' + recipient;
                } else if (containsExact(client + ':' + senderDomain + ';' + qualifier + '>' + recipientDomain)) {
                    return senderDomain + ';' + qualifier + '>' + recipientDomain;
                } else {
                    String host = findHost(client, senderDomain.substring(1), qualifier, recipient, recipientDomain);
                    if (host != null) {
                        return host;
                    } else {
                        int index3 = senderDomain.length();
                        while ((index3 = senderDomain.lastIndexOf('.', index3 - 1)) > index2) {
                            String subdomain = senderDomain.substring(0, index3 + 1);
                            if (containsExact(subdomain)) {
                                return subdomain;
                            } else if (containsExact(subdomain + '>' + recipient)) {
                                return subdomain + '>' + recipient;
                            } else if (containsExact(subdomain + '>' + recipientDomain)) {
                                return subdomain + '>' + recipientDomain;
                            } else if (containsExact(subdomain + ';' + qualifier)) {
                                return subdomain + ';' + qualifier;
                            } else if (containsExact(subdomain + ';' + qualifier + '>' + recipient)) {
                                return subdomain + ';' + qualifier + '>' + recipient;
                            } else if (containsExact(subdomain + ';' + qualifier + '>' + recipientDomain)) {
                                return subdomain + ';' + qualifier + '>' + recipientDomain;
                            } else if (containsExact(client + ':' + subdomain)) {
                                return subdomain;
                            } else if (containsExact(client + ':' + subdomain + '>' + recipient)) {
                                return subdomain + '>' + recipient;
                            } else if (containsExact(client + ':' + subdomain + '>' + recipientDomain)) {
                                return subdomain + '>' + recipientDomain;
                            } else if (containsExact(client + ':' + subdomain + ';' + qualifier)) {
                                return subdomain + ';' + qualifier;
                            } else if (containsExact(client + ':' + subdomain + ';' + qualifier + '>' + recipient)) {
                                return subdomain + ';' + qualifier + '>' + recipient;
                            } else if (containsExact(client + ':' + subdomain + ';' + qualifier + '>' + recipientDomain)) {
                                return subdomain + ';' + qualifier + '>' + recipientDomain;
                            }
                        }
                        int index4 = sender.length();
                        while ((index4 = sender.lastIndexOf('.', index4 - 1)) > index2) {
                            String subsender = sender.substring(0, index4 + 1);
                            if (containsExact(subsender)) {
                                return subsender;
                            } else if (containsExact(subsender + '>' + recipient)) {
                                return subsender + '>' + recipient;
                            } else if (containsExact(subsender + '>' + recipientDomain)) {
                                return subsender + '>' + recipientDomain;
                            } else if (containsExact(subsender + ';' + qualifier)) {
                                return subsender + ';' + qualifier;
                            } else if (containsExact(subsender + ';' + qualifier + '>' + recipient)) {
                                return subsender + ';' + qualifier + '>' + recipient;
                            } else if (containsExact(subsender + ';' + qualifier + '>' + recipientDomain)) {
                                return subsender + ';' + qualifier + '>' + recipientDomain;
                            } else if (containsExact(client + ':' + subsender)) {
                                return subsender;
                            } else if (containsExact(client + ':' + subsender + '>' + recipient)) {
                                return subsender + '>' + recipient;
                            } else if (containsExact(client + ':' + subsender + '>' + recipientDomain)) {
                                return subsender + '>' + recipientDomain;
                            } else if (containsExact(client + ':' + subsender + ';' + qualifier)) {
                                return subsender + ';' + qualifier;
                            } else if (containsExact(client + ':' + subsender + ';' + qualifier + '>' + recipient)) {
                                return subsender + ';' + qualifier + '>' + recipient;
                            } else if (containsExact(client + ':' + subsender + ';' + qualifier + '>' + recipientDomain)) {
                                return subsender + ';' + qualifier + '>' + recipientDomain;
                            }
                        }
                    }
                }
                if (senderDomain.endsWith(".br")) {
                    whoisSet.add(senderDomain);
                }
                regexSet.add(sender);
                regexSet.add(senderDomain);
            }
            // Verifica o HELO.
            if ((helo = Domain.extractHost(helo, true)) != null) {
                String host = findHost(client, helo, qualifier, recipient, recipientDomain);
                if (host != null) {
                    return host;
                }
                if (helo.endsWith(".br") && CacheHELO.match(ip, helo)) {
                    whoisSet.add(helo);
                }
                regexSet.add(helo);
            }
            // Verifica o IP.
            if (ip != null) {
                ip = Subnet.normalizeIP(ip);
                if (containsExact(ip)) {
                    return ip;
                } else if (containsExact(ip + '>' + recipient)) {
                    return ip + '>' + recipient;
                } else if (containsExact(ip + '>' + recipientDomain)) {
                    return ip + '>' + recipientDomain;
                } else if (containsExact(ip + ';' + qualifier)) {
                    return ip + ';' + qualifier;
                } else if (containsExact(ip + ';' + qualifier + '>' + recipient)) {
                    return ip + ';' + qualifier + '>' + recipient;
                } else if (containsExact(ip + ';' + qualifier + '>' + recipientDomain)) {
                    return ip + ';' + qualifier + '>' + recipientDomain;
                } else if (containsExact(client + ':' + ip)) {
                    return ip;
                } else if (containsExact(client + ':' + ip + '>' + recipient)) {
                    return ip + '>' + recipient;
                } else if (containsExact(client + ':' + ip + '>' + recipientDomain)) {
                    return ip + '>' + recipientDomain;
                } else if (containsExact(client + ':' + ip + ';' + qualifier)) {
                    return ip + ';' + qualifier;
                } else if (containsExact(client + ':' + ip + ';' + qualifier + '>' + recipient)) {
                    return ip + ';' + qualifier + '>' + recipient;
                } else if (containsExact(client + ':' + ip + ';' + qualifier + '>' + recipientDomain)) {
                    return ip + ';' + qualifier + '>' + recipientDomain;
                }
                whoisSet.add(ip);
                regexSet.add(ip);
            }
            // Verifica o CIDR.
            if (ip != null) {
                TreeSet<String> subSet = new TreeSet<String>();
                subSet.addAll(subSet("CIDR=", "CIDR>"));
                subSet.addAll(subSet(client + ":CIDR=", client + ":CIDR>"));
                for (String cidr : subSet) {
                    int index = cidr.indexOf('=');
                    cidr = cidr.substring(index + 1);
                    if (Subnet.containsIP(cidr, ip)) {
                        return cidr;
                    }
                }
            }
            // Verifica um critério do REGEX.
            if (!regexSet.isEmpty()) {
                TreeSet<String> subSet = new TreeSet<String>();
                subSet.addAll(subSet("REGEX=", "REGEX>"));
                subSet.addAll(subSet(client + ":REGEX=", client + ":REGEX>"));
                for (String whois : subSet) {
                    int index = whois.indexOf('=');
                    String regex = whois.substring(index + 1);
                    for (String token : regexSet) {
                        if (matches(regex, token)) {
                            return regex;
                        }
                    }
                }
            }
            // Verifica critérios do WHOIS.
            if (!whoisSet.isEmpty()) {
                TreeSet<String> subSet = new TreeSet<String>();
                subSet.addAll(subSet("WHOIS/", "WHOIS<"));
                subSet.addAll(subSet(client + ":WHOIS/", client + ":WHOIS<"));
                for (String whois : subSet) {
                    int indexKey = whois.indexOf('/');
                    char signal = '=';
                    int indexValue = whois.indexOf(signal);
                    if (indexValue == -1) {
                        signal = '<';
                        indexValue = whois.indexOf(signal);
                        if (indexValue == -1) {
                            signal = '>';
                            indexValue = whois.indexOf(signal);
                        }
                    }
                    if (indexValue != -1) {
                        String key = whois.substring(indexKey + 1, indexValue);
                        String criterion = whois.substring(indexValue + 1);
                        for (String token : whoisSet) {
                            String value = null;
                            if (Subnet.isValidIP(token)) {
                                value = Subnet.getValue(token, key);
                            } else if (!token.startsWith(".") && Domain.containsDomain(token)) {
                                value = Domain.getValue(token, key);
                            } else if (!token.startsWith(".") && Domain.containsDomain(token.substring(1))) {
                                value = Domain.getValue(token, key);
                            }
                            if (value != null) {
                                if (signal == '=') {
                                    if (criterion.equals(value)) {
                                        return whois;
                                    }
                                } else if (value.length() > 0) {
                                    int criterionInt = parseIntWHOIS(criterion);
                                    int valueInt = parseIntWHOIS(value);
                                    if (signal == '<' && valueInt < criterionInt) {
                                        return whois;
                                    } else if (signal == '>' && valueInt > criterionInt) {
                                        return whois;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return null;
        }
        
        private static int parseIntWHOIS(String value) {
            try {
                if (value == null || value.length() == 0) {
                    return 0;
                } else {
                    Date date = Domain.DATE_FORMATTER.parse(value);
                    long time = date.getTime() / (1000 * 60 * 60 * 24);
                    long today = System.currentTimeMillis() / (1000 * 60 * 60 * 24);
                    return (int) (today - time);
                }
            } catch (Exception ex) {
                try {
                    return Integer.parseInt(value);
                } catch (Exception ex2) {
                    return 0;
                }
            }
        }

        private static String findHost(String client,
                String host, String qualifier,
                String recipient, String recipientDomain) {
            do {
                int index = host.indexOf('.') + 1;
                host = host.substring(index);
                String token = '.' + host;
                if (containsExact(token)) {
                    return token;
                } else if (containsExact(token + '>' + recipient)) {
                    return token + '>' + recipient;
                } else if (containsExact(token + '>' + recipientDomain)) {
                    return token + '>' + recipientDomain;
                } else if (containsExact(token + ';' + qualifier)) {
                    return token + ';' + qualifier;
                } else if (containsExact(token + ';' + qualifier + '>' + recipient)) {
                    return token + ';' + qualifier + '>' + recipient;
                } else if (containsExact(token + ';' + qualifier + '>' + recipientDomain)) {
                    return token + ';' + qualifier + '>' + recipientDomain;
                } else if (containsExact(client + ':' + token)) {
                    return token;
                } else if (containsExact(client + ':' + token + '>' + recipient)) {
                    return token + '>' + recipient;
                } else if (containsExact(client + ':' + token + '>' + recipientDomain)) {
                    return token + '>' + recipientDomain;
                } else if (containsExact(client + ':' + token + ';' + qualifier)) {
                    return token + ';' + qualifier;
                } else if (containsExact(client + ':' + token + ';' + qualifier + '>' + recipient)) {
                    return token + ';' + qualifier + '>' + recipient;
                } else if (containsExact(client + ':' + token + ';' + qualifier + '>' + recipientDomain)) {
                    return token + ';' + qualifier + '>' + recipientDomain;
                }
            } while (host.contains("."));
            return null;
        }

        private static void store() {
            if (CHANGED) {
                try {
                    long time = System.currentTimeMillis();
                    File file = new File("./data/block.set");
                    TreeSet<String> set = getAll();
                    FileOutputStream outputStream = new FileOutputStream(file);
                    try {
                        SerializationUtils.serialize(set, outputStream);
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

        private static void load() {
            long time = System.currentTimeMillis();
            File file = new File("./data/block.set");
            if (file.exists()) {
                try {
                    Set<String> set;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        set = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    // Processo temporário de transição.
                    for (String token : set) {
                        String client;
                        String identifier;
                        if (token.contains(":")) {
                            int index = token.indexOf(':');
                            client = token.substring(0, index);
                            identifier = token.substring(index + 1);
                        } else {
                            client = null;
                            identifier = token;
                        }
                        if (Subnet.isValidCIDR(identifier)) {
                            identifier = "CIDR=" + Subnet.normalizeCIDR(identifier);
                        } else if (Owner.isOwnerID(identifier)) {
                            identifier = "WHOIS/ownerid=" + identifier;
                        }
                        if (client == null) {
                            addExact(identifier);
                        } else {
                            addExact(client + ':' + identifier);
                        }
                    }
                    CHANGED = false;
                    Server.logLoad(time, file);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }
    }

    public static boolean addBlock(String token) throws ProcessException {
        return CacheBlock.add(token);
    }
    
    public static boolean addBlockExact(String token) {
        return CacheBlock.addExact(token);
    }

    public static boolean addBlock(String client, String sender) throws ProcessException {
        return CacheBlock.add(client, sender);
    }

    public static boolean dropBlock(String token) throws ProcessException {
        return CacheBlock.drop(token);
    }
    
    public static boolean dropAllBlock() throws ProcessException {
        return CacheBlock.dropAll();
    }

    public static boolean dropBlock(String client, String sender) throws ProcessException {
        return CacheBlock.drop(client, sender);
    }

    public static TreeSet<String> getBlockSet(String client) throws ProcessException {
        return CacheBlock.get(client);
    }

    public static TreeSet<String> getAllBlockSet(String client) throws ProcessException {
        return CacheBlock.getAll(client);
    }

    public static TreeSet<String> getProviderSet() throws ProcessException {
        return CacheProvider.getAll();
    }
    
    public static boolean containsBlock(String token) {
        return CacheBlock.containsExact(token);
    }

    public static TreeSet<String> getBlockSet() throws ProcessException {
        return CacheBlock.get();
    }

    public static TreeSet<String> getAllBlockSet() throws ProcessException {
        return CacheBlock.getAll();
    }

    public static TreeSet<String> clear(String token) {
        TreeSet<String> clearSet = new TreeSet<String>();
        TreeMap<String,Distribution> distribuitonMap = CacheDistribution.getAll(token);
        for (String key : distribuitonMap.keySet()) {
            Distribution distribution = distribuitonMap.get(key);
            if (distribution != null && distribution.clear()) {
                clearSet.add(key);
                Peer.sendToAll(key, distribution);
            }
            if (CacheBlock.dropExact(key)) {
                clearSet.add(key);
            }
        }
        for (String key : CacheBlock.getAllTokens(token)) {
            if (CacheBlock.dropExact(key)) {
                clearSet.add(key);
            }
        }
        if (Peer.dropAllReputation(token)) {
            clearSet.add(token);
        }
        return clearSet;
    }

    /**
     * Classe que representa o cache de tokens que devem ser ignorados na
     * reclamação.
     */
    private static class CacheIgnore {

        /**
         * Conjunto de remetentes em ignorelist.
         */
        private static final TreeSet<String> SET = new TreeSet<String>();
        /**
         * Flag que indica se o cache foi modificado.
         */
        private static boolean CHANGED = false;
        
        private static boolean dropExact(String token) {
            if (SET.remove(token)) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }

        private static boolean addExact(String token) {
            if (SET.add(token)) {
                Peer.rejectAll(token);
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }
        
        private static synchronized TreeSet<String> getAll() throws ProcessException {
            TreeSet<String> ignoreSet = new TreeSet<String>();
            ignoreSet.addAll(SET);
            return ignoreSet;
        }

        private static boolean containsExact(String address) {
            return SET.contains(address);
        }

        private static synchronized Set<String> subSet(String begin, String end) {
            return SET.subSet(begin, false, end, false);
        }

        private static boolean add(String token) throws ProcessException {
            if ((token = normalizeTokenCIDR(token)) == null) {
                throw new ProcessException("ERROR: TOKEN INVALID");
            } else if (addExact(token)) {
                return true;
            } else {
                return false;
            }
        }
        
        private static TreeSet<String> dropAll() throws ProcessException {
            TreeSet<String> ignoreSet = new TreeSet<String>();
            for (String token : getAll()) {
                if (dropExact(token)) {
                    ignoreSet.add(token);
                }
            }
            return ignoreSet;
        }

        private static boolean drop(String token) throws ProcessException {
            if ((token = normalizeTokenCIDR(token)) == null) {
                throw new ProcessException("ERROR: TOKEN INVALID");
            } else if (dropExact(token)) {
                return true;
            } else {
                return false;
            }
        }
        
        private static boolean contains(String token) {
            if (token == null) {
                return false;
            } else {
                // Verifica o remetente.
                if (token.contains("@")) {
                    String sender = token.toLowerCase();
                    int index1 = sender.indexOf('@');
                    int index2 = sender.lastIndexOf('@');
                    String part = sender.substring(0, index1 + 1);
                    String senderDomain = sender.substring(index2);
                    if (containsExact(sender)) {
                        return true;
                    } else if (containsExact(part)) {
                        return true;
                    } else if (containsExact(senderDomain)) {
                        return true;
                    } else if (containsHost(senderDomain.substring(1))) {
                        return true;
                    } else {
                        int index3 = senderDomain.length();
                        while ((index3 = senderDomain.lastIndexOf('.', index3 - 1)) > index2) {
                            String subdomain = senderDomain.substring(0, index3 + 1);
                            if (containsExact(subdomain)) {
                                return true;
                            }
                        }
                        int index4 = sender.length();
                        while ((index4 = sender.lastIndexOf('.', index4 - 1)) > index2) {
                            String subsender = sender.substring(0, index4 + 1);
                            if (containsExact(subsender)) {
                                return true;
                            }
                        }
                    }
                }
                // Verifica o HELO.
                String helo;
                if ((helo = Domain.extractHost(token, true)) != null) {
                    if (containsHost(helo)) {
                        return true;
                    }
                }
                // Verifica o IP.
                String ip;
                if (Subnet.isValidIP(token)) {
                    ip = Subnet.normalizeIP(token);
                    if (containsExact(ip)) {
                        return true;
                    }
                    // Verifica o CIDR.
                    for (String cidr : subSet("CIDR=", "CIDR>")) {
                        int index = cidr.indexOf('=');
                        cidr = cidr.substring(index + 1);
                        if (Subnet.containsIP(cidr, ip)) {
                            return true;
                        }
                    }
                }
                return false;
            }
        }

        private static boolean containsHost(String host) {
            do {
                int index = host.indexOf('.') + 1;
                host = host.substring(index);
                String token = '.' + host;
                if (containsExact(token)) {
                    return true;
                }
            } while (host.contains("."));
            return false;
        }

        private static void store() {
            if (CHANGED) {
                try {
                    long time = System.currentTimeMillis();
                    File file = new File("./data/ignore.set");
                    TreeSet<String> set = getAll();
                    FileOutputStream outputStream = new FileOutputStream(file);
                    try {
                        SerializationUtils.serialize(set, outputStream);
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

        private static void load() {
            long time = System.currentTimeMillis();
            File file = new File("./data/ignore.set");
            if (file.exists()) {
                try {
                    Set<String> set;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        set = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    // Processo temporário de transição.
                    for (String token : set) {
                        String client;
                        String identifier;
                        if (token.contains(":")) {
                            int index = token.indexOf(':');
                            client = token.substring(0, index);
                            identifier = token.substring(index + 1);
                        } else {
                            client = null;
                            identifier = token;
                        }
                        if (Subnet.isValidCIDR(identifier)) {
                            identifier = "CIDR=" + Subnet.normalizeCIDR(identifier);
                        }
                        if (client == null) {
                            addExact(identifier);
                        } else {
                            addExact(client + ':' + identifier);
                        }
                    }
                    CHANGED = false;
                    Server.logLoad(time, file);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }
    }

    public static boolean isIgnore(String token) {
        return CacheIgnore.contains(token);
    }

    public static boolean addIgnore(String token) throws ProcessException {
        return CacheIgnore.add(token);
    }
    
    public static TreeSet<String> dropAllIgnore() throws ProcessException {
        return CacheIgnore.dropAll();
    }

    public static boolean dropIgnore(String token) throws ProcessException {
        return CacheIgnore.drop(token);
    }

    public static TreeSet<String> getIgnoreSet() throws ProcessException {
        return CacheIgnore.getAll();
    }

    public static TreeSet<String> getGuessSet() throws ProcessException {
        return CacheGuess.get();
    }
    
    public static HashMap<String,String> getGuessMap() throws ProcessException {
        return CacheGuess.getMap();
    }


    /**
     * Classe que representa o cache de "best-guess" exclusivos.
     */
    private static class CacheGuess {

        /**
         * http://www.openspf.org/FAQ/Best_guess_record porém compatível com
         * IPv6
         */
        private static final String BEST_GUESS = "v=spf1 a/24//48 mx/24//48 ptr ?all";
        /**
         * Mapa de registros manuais de SPF caso o domínio não tenha um.
         */
        private static final HashMap<String,String> MAP = new HashMap<String,String>();
        /**
         * Flag que indica se o cache foi modificado.
         */
        private static boolean CHANGED = false;
        
        private static synchronized String dropExact(String token) {
            String ret = MAP.remove(token);
            if (ret == null) {
                return null;
            } else {
                CHANGED = true;
                return ret;
            }
        }

        private static synchronized String putExact(String key, String value) {
            String ret = MAP.put(key, value);
            if (!value.equals(ret)) {
                CHANGED = true;
            }
            return ret;
        }
        
        private static synchronized TreeSet<String> keySet() {
            TreeSet<String> keySet = new TreeSet<String>();
            keySet.addAll(MAP.keySet());
            return keySet;
        }
        
        private static synchronized HashMap<String,String> getMap() {
            HashMap<String,String> map = new HashMap<String,String>();
            map.putAll(MAP);
            return map;
        }

        private static synchronized boolean containsExact(String address) {
            return MAP.containsKey(address);
        }
        
        private static synchronized String getExact(String host) {
            return MAP.get(host);
        }
        
        private static synchronized boolean isChanged() {
            return CHANGED;
        }
        
        private static synchronized void setStored() {
            CHANGED = false;
        }
        
        private static synchronized void setLoaded() {
            CHANGED = false;
        }

        private static boolean add(String hostname,
                String spf) throws ProcessException {
            hostname = Domain.extractHost(hostname, false);
            if (!Domain.containsDomain(hostname)) {
                throw new ProcessException("ERROR: HOSTNAME INVALID");
            } else if (!spf.equals(putExact("." + hostname, spf))) {
                CacheSPF.refresh(hostname, true);
                return true;
            } else {
                return false;
            }
        }
        
        private static TreeSet<String> dropAll() throws ProcessException {
            TreeSet<String> guessSet = new TreeSet<String>();
            for (String domain : keySet()) {
                String spf = dropExact(domain);
                if (spf != null) {
                    guessSet.add(domain + " \"" + spf + "\"");
                }
            }
            return guessSet;
        }

        private static boolean drop(String hostname) throws ProcessException {
            hostname = Domain.extractHost(hostname, false);
            if (!Domain.containsDomain(hostname)) {
                throw new ProcessException("ERROR: HOSTNAME INVALID");
            } else if (dropExact("." + hostname) == null) {
                return false;
            } else {
                CacheSPF.refresh(hostname, true);
                return true;
            }
        }

        private static boolean contains(String host) {
            if (!host.startsWith(".")) {
                host = "." + host;
            }
            return containsExact(host);
        }

        private static TreeSet<String> get() throws ProcessException {
            TreeSet<String> guessSet = new TreeSet<String>();
            for (String domain : keySet()) {
                String spf = get(domain);
                guessSet.add(domain + " \"" + spf + "\"");
            }
            return guessSet;
        }

        private static String get(String host) {
            if (!host.startsWith(".")) {
                host = "." + host;
            }
            String guess = getExact(host);
            if (guess == null) {
                // Se não hoouver palpite SPF específico para o hostname,
                // utilizar o palpite padrão, porém adaptado para IPv6.
                // http://www.openspf.org/FAQ/Best_guess_record
                return BEST_GUESS;
            } else {
                // Significa que um palpite SPF específico
                // foi registrado para este hostname.
                // Neste caso utilizar o paltpite específico.
                return guess;
            }
        }

        private static void store() {
            if (isChanged()) {
                try {
                    long time = System.currentTimeMillis();
                    File file = new File("./data/guess.map");
                    HashMap<String,String> map = getMap();
                    FileOutputStream outputStream = new FileOutputStream(file);
                    try {
                        SerializationUtils.serialize(map, outputStream);
                        setStored();
                    } finally {
                        outputStream.close();
                    }
                    Server.logStore(time, file);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }

        private static void load() {
            long time = System.currentTimeMillis();
            File file = new File("./data/guess.map");
            if (file.exists()) {
                try {
                    HashMap<String,String> map;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        map = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    for (String key : map.keySet()) {
                        String value = map.get(key);
                        putExact(key, value);
                    }
                    setLoaded();
                    Server.logLoad(time, file);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }
    }

    public static boolean addGuess(String host, String spf) throws ProcessException {
        return CacheGuess.add(host, spf);
    }

    public static boolean dropGuess(String host) throws ProcessException {
        return CacheGuess.drop(host);
    }
    
    public static TreeSet<String> dropAllGuess() throws ProcessException {
        return CacheGuess.dropAll();
    }

    public static void storeProvider() {
        CacheProvider.store();
    }

    public static void storeIgnore() {
        CacheIgnore.store();
    }

    public static void storeBlock() {
        CacheBlock.store();
    }

    public static void storeGuess() {
        CacheGuess.store();
    }

//    public static void storePeer() {
//        CachePeer.store();
//    }

    public static void storeTrap() {
        CacheTrap.store();
    }

    public static void storeWhite() {
        CacheWhite.store();
    }

    public static void storeDistribution() {
        CacheDistribution.store();
    }

    public static void storeSPF() {
        CacheSPF.store();
    }

    /**
     * Armazenamento de cache em disco.
     */
    public static void store() {
        CacheSPF.store();
        CacheComplain.store();
        CacheDistribution.store();
        CacheProvider.store();
        CacheTrap.store();
        CacheWhite.store();
        CacheIgnore.store();
        CacheBlock.store();
        CacheGuess.store();
        CacheHELO.store();
        CacheDefer.store();
//        CachePeer.store();
    }

    /**
     * Carregamento de cache do disco.
     */
    public static void load() {
        CacheSPF.load();
        CacheComplain.load();
        CacheDistribution.load();
        CacheProvider.load();
        CacheTrap.load();
        CacheWhite.load();
        CacheIgnore.load();
        CacheBlock.load();
        CacheGuess.load();
        CacheHELO.load();
        CacheDefer.load();
//        CachePeer.load();
    }

    /**
     * Classe que representa o cache de resolução de HELO.
     */
    private static class CacheHELO {

        /**
         * Mapa de atributos da verificação de HELO.
         */
        private static final HashMap<String,HELO> MAP = new HashMap<String,HELO>();
        /**
         * O próximo registro HELO que deve ser atualizado.
         */
        private static String hostRefresh = null;
        private static HELO heloRefresh = null;
        /**
         * Flag que indica se o cache foi modificado.
         */
        private static boolean CHANGED = false;
        
        private static synchronized HELO dropExact(String token) {
            HELO ret = MAP.remove(token);
            if (ret != null) {
                CHANGED = true;
            }
            return ret;
        }

        private static synchronized HELO putExact(String key, HELO value) {
            HELO ret = MAP.put(key, value);
            if (!value.equals(ret)) {
                CHANGED = true;
            }
            return ret;
        }
        
        private static synchronized TreeSet<String> keySet() {
            TreeSet<String> keySet = new TreeSet<String>();
            keySet.addAll(MAP.keySet());
            return keySet;
        }
        
        private static synchronized ArrayList<HELO> values() {
            ArrayList<HELO> values = new ArrayList<HELO>();
            values.addAll(MAP.values());
            return values;
        }
        
        private static synchronized HashMap<String,HELO> getMap() {
            HashMap<String,HELO> map = new HashMap<String,HELO>();
            map.putAll(MAP);
            return map;
        }
        
        private static synchronized HELO getExact(String host) {
            return MAP.get(host);
        }
        
        private static synchronized String getRefreshHELO() {
            String helo = hostRefresh;
            hostRefresh = null;
            heloRefresh = null;
            return helo;
        }
        
        private static synchronized void addQuery(String host, HELO helo) {
            helo.queryCount++;
            helo.lastQuery = System.currentTimeMillis();
            if (hostRefresh == null || heloRefresh == null) {
                hostRefresh = host;
                heloRefresh = helo;
            } else if (heloRefresh.queryCount < helo.queryCount) {
                hostRefresh = host;
                heloRefresh = helo;
            }
        }

        /*
         * Classe para guardar os atributos da consulta.
         */
        private static final class HELO implements Serializable {

            private static final long serialVersionUID = 1L;
            private Attributes attributes = null;
            private TreeSet<String> addressSet = null;
            private String address4 = null;
            private String address6 = null;
            private int queryCount = 0;
            private long lastQuery;
            
            private HELO(String hostname) {
                this.lastQuery = System.currentTimeMillis();
                refresh(hostname);
            }

            public synchronized void refresh(String hostname) {
                long time = System.currentTimeMillis();
                try {
                    TreeSet<String> ipv4Set = new TreeSet<String>();
                    TreeSet<String> ipv6Set = new TreeSet<String>();
                    Attributes attributesA = Server.getAttributesDNS(
                            hostname, new String[]{"A"});
                    if (attributesA != null) {
                        Enumeration enumerationA = attributesA.getAll();
                        while (enumerationA.hasMoreElements()) {
                            Attribute attributeA = (Attribute) enumerationA.nextElement();
                            NamingEnumeration enumeration = attributeA.getAll();
                            while (enumeration.hasMoreElements()) {
                                String address = (String) enumeration.next();
                                if (SubnetIPv4.isValidIPv4(address)) {
                                    address = SubnetIPv4.normalizeIPv4(address);
                                    ipv4Set.add(address);
                                }
                            }
                        }
                        Attributes attributesAAAA = Server.getAttributesDNS(
                                hostname, new String[]{"AAAA"});
                        if (attributesAAAA != null) {
                            Enumeration enumerationAAAA = attributesAAAA.getAll();
                            while (enumerationAAAA.hasMoreElements()) {
                                Attribute attributeAAAA = (Attribute) enumerationAAAA.nextElement();
                                NamingEnumeration enumeration = attributeAAAA.getAll();
                                while (enumeration.hasMoreElements()) {
                                    String address = (String) enumeration.next();
                                    if (SubnetIPv6.isValidIPv6(address)) {
                                        address = SubnetIPv6.normalizeIPv6(address);
                                        ipv6Set.add(address);
                                    }
                                }
                            }
                        }
                    }
                    this.addressSet = new TreeSet<String>();
                    this.addressSet.addAll(ipv4Set);
                    this.addressSet.addAll(ipv6Set);
                    if (ipv4Set.size() == 1) {
                        this.address4 = ipv4Set.first();
                    } else {
                        this.address4 = null;
                    }
                    if (ipv6Set.size() == 1) {
                        this.address6 = ipv6Set.first();
                    } else {
                        this.address6 = null;
                    }
                    Server.logLookupHELO(time, hostname, addressSet.toString());
                } catch (CommunicationException ex) {
                    Server.logLookupHELO(time, hostname, "TIMEOUT");
                } catch (NameNotFoundException ex) {
                    this.addressSet = null;
                    this.address4 = null;
                    this.address6 = null;
                    Server.logLookupHELO(time, hostname, "NXDOMAIN");
                } catch (NamingException ex) {
                    this.addressSet = null;
                    this.address4 = null;
                    this.address6 = null;
                    Server.logLookupHELO(time, hostname, "ERROR " + ex.getExplanation());
                } finally {
                    this.attributes = null;
                    this.queryCount = 0;
                    CHANGED = true;
                }
            }
            
            public synchronized TreeSet<String> getAddressSet() {
                TreeSet<String> set = new TreeSet<String>();
                set.addAll(this.addressSet);
                return set;
            }
            
            public synchronized boolean contains(String ip) {
                if ((ip = Subnet.normalizeIP(ip)) == null) {
                    return false;
                } else if (addressSet == null) {
                    return false;
                } else {
                    return addressSet.contains(ip);
                }
            }
            
            public synchronized String getAddress4() {
                return address4;
            }
            
            public synchronized String getAddress6() {
                return address6;
            }

            public synchronized boolean isExpired7() {
                return System.currentTimeMillis() - lastQuery > 604800000;
            }
            
            public synchronized boolean isExpired14() {
                return System.currentTimeMillis() - lastQuery > 1209600000;
            }

            private synchronized void update() {
                if (attributes != null) {
                    TreeSet<String> ipv4Set = new TreeSet<String>();
                    TreeSet<String> ipv6Set = new TreeSet<String>();
                    Enumeration enumeration = attributes.getAll();
                    while (enumeration.hasMoreElements()) {
                        try {
                            Attribute attribute = (Attribute) enumeration.nextElement();
                            NamingEnumeration namingEnumeration = attribute.getAll();
                            while (namingEnumeration.hasMoreElements()) {
                                String address = (String) namingEnumeration.next();
                                if (SubnetIPv4.isValidIPv4(address)) {
                                    address = SubnetIPv4.normalizeIPv4(address);
                                    ipv4Set.add(address);
                                } else if (SubnetIPv6.isValidIPv6(address)) {
                                    address = SubnetIPv6.normalizeIPv6(address);
                                    ipv6Set.add(address);
                                }
                            }
                        } catch (NamingException ex) {
                        }
                    }
                    this.addressSet = new TreeSet<String>();
                    this.addressSet.addAll(ipv4Set);
                    this.addressSet.addAll(ipv6Set);
                    if (ipv4Set.size() == 1) {
                        this.address4 = ipv4Set.first();
                    } else {
                        this.address4 = null;
                    }
                    if (ipv6Set.size() == 1) {
                        this.address6 = ipv6Set.first();
                    } else {
                        this.address6 = null;
                    }
                    this.attributes = null;
                }
            }
        }
        
        public static String getUniqueIPv4(String helo) {
            if ((helo = Domain.extractHost(helo, false)) == null) {
                return null;
            } else {
                HELO heloObj = getExact(helo);
                if (heloObj == null) {
                    return null;
                } else {
                    return heloObj.getAddress4();
                }
            }
        }
        
        public static String getUniqueIPv6(String helo) {
            if ((helo = Domain.extractHost(helo, false)) == null) {
                return null;
            } else {
                HELO heloObj = getExact(helo);
                if (heloObj == null) {
                    return null;
                } else {
                    return heloObj.getAddress6();
                }
            }
        }

        public static boolean match(String ip, String helo) {
            if ((helo = Domain.extractHost(helo, false)) == null) {
                return false;
            } else {
                HELO heloObj = getExact(helo);
                if (heloObj == null) {
                    heloObj = new HELO(helo);
                    putExact(helo, heloObj);
                } else {
                    addQuery(helo, heloObj);
                    CHANGED = true;
                }
                return heloObj.contains(ip);
            }
        }

        private static void dropExpired() {
            for (String helo : keySet()) {
                long time = System.currentTimeMillis();
                HELO heloObj = getExact(helo);
                if (heloObj != null && heloObj.isExpired14()) {
                    heloObj = dropExact(helo);
                    if (heloObj != null) {
                        Server.logLookupHELO(time, helo, "EXPIRED");
                    }
                }
            }
        }

        /**
         * Atualiza o registro mais consultado.
         */
        private static void refresh() {
            String heloMax = getRefreshHELO();
            HELO heloObjMax = getExact(heloMax);
            if (heloObjMax == null) {
                for (String hostname : keySet()) {
                    HELO heloObj = getExact(hostname);
                    if (heloObj != null) {
                        if (heloObjMax == null) {
                            heloMax = hostname;
                            heloObjMax = heloObj;
                        } else if (heloObjMax.queryCount < heloObj.queryCount) {
                            heloMax = hostname;
                            heloObjMax = heloObj;
                        }
                    }
                }
            }
            if (heloMax != null && heloObjMax != null && heloObjMax.queryCount > 3) {
                heloObjMax.refresh(heloMax);
            }
        }

        private static void store() {
            if (CHANGED) {
                try {
                    long time = System.currentTimeMillis();
                    File file = new File("./data/helo.map");
                    HashMap<String,HELO> map = getMap();
                    FileOutputStream outputStream = new FileOutputStream(file);
                    try {
                        SerializationUtils.serialize(map, outputStream);
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

        private static void load() {
            long time = System.currentTimeMillis();
            File file = new File("./data/helo.map");
            if (file.exists()) {
                try {
                    HashMap<String,Object> map;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        map = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    for (String key : map.keySet()) {
                        Object value = map.get(key);
                        if (value instanceof HELO) {
                            HELO helo = (HELO) value;
                            helo.update();
                            putExact(key, helo);
                        }
                    }
                    CHANGED = false;
                    Server.logLoad(time, file);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }
    }
    
    public static void dropExpiredHELO() {
        CacheHELO.dropExpired();
    }

    /**
     * Classe que representa um atrazo programado.
     */
    private static class CacheDefer {

        /**
         * Mapa de atrazos programados.
         */
        private static final HashMap<String,Long> MAP = new HashMap<String,Long>();
        /**
         * Flag que indica se o cache foi modificado.
         */
        private static boolean CHANGED = false;
        
        private static synchronized Long dropExact(String token) {
            Long ret = MAP.remove(token);
            if (ret != null) {
                CHANGED = true;
            }
            return ret;
        }

        private static synchronized Long putExact(String key, Long value) {
            Long ret = MAP.put(key, value);
            if (!value.equals(ret)) {
                CHANGED = true;
            }
            return ret;
        }
        
        private static synchronized TreeSet<String> keySet() {
            TreeSet<String> keySet = new TreeSet<String>();
            keySet.addAll(MAP.keySet());
            return keySet;
        }
        
        private static synchronized HashMap<String,Long> getMap() {
            HashMap<String,Long> map = new HashMap<String,Long>();
            map.putAll(MAP);
            return map;
        }

        private static boolean containsExact(String address) {
            return MAP.containsKey(address);
        }
        
        private static Long getExact(String host) {
            return MAP.get(host);
        }
        
        private static synchronized boolean isChanged() {
            return CHANGED;
        }
        
        private static synchronized void setStored() {
            CHANGED = false;
        }
        
        private static synchronized void setLoaded() {
            CHANGED = false;
        }

        public static void dropExpired() {
            long expire = System.currentTimeMillis() - (5 * 24 * 60 * 60 * 1000); // Expira em cinco dias
            for (String id : keySet()) {
                Long start = getExact(id);
                if (start != null && start < expire) {
                    drop(id);
                }
            }
        }

        public static boolean defer(String id, int minutes) {
            if (id == null) {
                return false;
            } else {
                id = id.trim().toLowerCase();
                long now = System.currentTimeMillis();
                Long start = getExact(id);
                if (start == null) {
                    start = now;
                    put(id, start);
                    return true;
                } else if (start < (now - minutes * 60 * 1000)) {
                    end(id);
                    return false;
                } else {
                    return true;
                }
            }
        }

        private static void end(String id) {
            long now = System.currentTimeMillis();
            if (dropExact(id) != null) {
                Server.logDefer(now, id, "END");
            }
        }

        private static void drop(String id) {
            long now = System.currentTimeMillis();
            if (dropExact(id) != null) {
                Server.logDefer(now, id, "EXPIRED");
            }
        }

        private static void put(String id, long start) {
            long now = System.currentTimeMillis();
            if (putExact(id, start) == null) {
                Server.logDefer(now, id, "START");
            }
        }

        private static void store() {
            if (isChanged()) {
                try {
                    long time = System.currentTimeMillis();
                    File file = new File("./data/defer.map");
                    HashMap<String,Long> map = getMap();
                    FileOutputStream outputStream = new FileOutputStream(file);
                    try {
                        SerializationUtils.serialize(map, outputStream);
                        setStored();
                    } finally {
                        outputStream.close();
                    }
                    Server.logStore(time, file);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }

        private static void load() {
            long time = System.currentTimeMillis();
            File file = new File("./data/defer.map");
            if (file.exists()) {
                try {
                    HashMap<String,Long> map;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        map = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    for (String key : map.keySet()) {
                        Long value = map.get(key);
                        putExact(key, value);
                    }
                    setLoaded();
                    Server.logLoad(time, file);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }
    }
    
    public static void dropExpiredDefer() {
        CacheDefer.dropExpired();
    }

    protected static String processPostfixSPF(
            String client, String ip, String sender, String helo,
            String recipient) throws ProcessException {
        if (sender == null) {
            sender = null;
        } else if (sender.trim().length() == 0) {
            sender = null;
        } else {
            sender = sender.toLowerCase();
        }
        if (!Domain.isEmail(recipient)) {
            recipient = null;
        }
        if (sender != null && !Domain.isEmail(sender)) {
            return "action=REJECT [RBL] "
                    + sender + " is not a valid e-mail address.\n\n";
        } else if (sender != null && Domain.isReserved(sender)) {
            return "action=REJECT [RBL] "
                    + sender + " has a reserved domain.\n\n";
        } else if (!Subnet.isValidIP(ip)) {
            return "action=REJECT [RBL] "
                    + ip + " is not a valid IP.\n\n";
        } else {
            try {
                TreeSet<String> tokenSet = new TreeSet<String>();
                ip = Subnet.normalizeIP(ip);
                tokenSet.add(Subnet.normalizeIP(ip));
                // Passar a acompanhar todos os 
                // HELO quando apontados para o IP para 
                // uma nova forma de interpretar dados.
                if (CacheHELO.match(ip, helo)) {
                    helo = Domain.normalizeHostname(helo, true);
                    tokenSet.add(helo);
                    String ipv4 = CacheHELO.getUniqueIPv4(helo);
                    if (ipv4 != null) {
                        // Equivalência de pilha dupla se 
                        // IPv4 for único para o HELO.
                        tokenSet.add(ipv4);
                    }
                    String ipv6 = CacheHELO.getUniqueIPv6(helo);
                    if (ipv6 != null) {
                        // Equivalência de pilha dupla se 
                        // IPv6 for único para o HELO.
                        tokenSet.add(ipv6);
                    }
                }
                String result;
                LinkedList<String> logList = new LinkedList<String>();
                SPF spf = CacheSPF.get(sender);
                if (spf == null) {
                    result = "NONE";
                } else if (spf.isDefinitelyInexistent()) {
                    // O domínio foi dado como inexistente inúmeras vezes.
                    // Rejeitar e denunciar o host pois há abuso de tentativas.
                    String ticket = SPF.addQuery(ip, sender, helo, tokenSet);
                    CacheComplain.addComplain(client, ticket);
                    return "action=REJECT [RBL] "
                            + "sender has non-existent internet domain.\n\n";
                } else if (spf.isInexistent()) {
                    return "action=REJECT [RBL] "
                            + "sender has non-existent internet domain.\n\n";
                } else {
                    result = spf.getResult(ip, sender, helo, logList);
                }
                String origem;
                String fluxo;
                if (result.equals("FAIL") && !CacheWhite.containsSender(client, sender, result, recipient)) {
                    String ticket = SPF.addQuery(ip, sender, helo, tokenSet);
                    CacheComplain.addComplain(client, ticket);
                    // Retornar REJECT somente se não houver 
                    // liberação literal do remetente com FAIL.
                    return "action=REJECT "
                            + "[SPF] " + sender + " is not allowed to "
                            + "send mail from " + ip + ". "
                            + "Please see http://www.openspf.org/why.html?"
                            + "sender=" + sender + "&"
                            + "ip=" + ip + " for details.\n\n";
                } else if (result.equals("PASS") || (sender != null && CacheProvider.containsHELO(ip, helo))) {
                    // Quando fo PASS, significa que o domínio
                    // autorizou envio pelo IP, portanto o dono dele
                    // é responsavel pelas mensagens.
                    String mx = Domain.extractHost(sender, true);
                    if (CacheProvider.containsExact(mx)) {
                        // Listar apenas o remetente se o
                        // hostname for um provedor de e-mail.
                        tokenSet.add(sender);
                        origem = sender;
                    } else {
                        // Não é um provedor então
                        // o MX deve ser listado.
                        tokenSet.add(mx);
                        origem = mx;
                    }
                    fluxo = origem + ">" + recipient;
                } else if (CacheHELO.match(ip, helo)) {
                    String dominio = Domain.extractDomain(helo, true);
                    origem = sender + ">" + dominio.substring(1);
                    fluxo = origem + ">" + recipient;
                } else {
                    origem = sender + ">" + ip;
                    fluxo = origem + ">" + recipient;
                }
                if (CacheWhite.contains(client, ip, sender, helo, result, recipient)) {
                    // Calcula frequencia de consultas.
                    String url = Core.getSpamURL();
                    String ticket = SPF.addQuery(ip, sender, helo, tokenSet);
                    return "action=PREPEND "
                            + "Received-SPFBL: " + result + " "
                            + (url == null ? "" : url) + ticket + "\n\n";
                } else if (CacheTrap.contains(client, recipient)) {
                    // Calcula frequencia de consultas.
                    String ticket = SPF.addQuery(ip, sender, helo, tokenSet);
                    CacheComplain.addComplain(client, ticket);
                    return "action=DISCARD [RBL] discarded by spamtrap.\n\n";
                } else if (SPF.isBlocked(tokenSet)) {
                    // Calcula frequencia de consultas.
                    String ticket = SPF.addQuery(ip, sender, helo, tokenSet);
                    CacheComplain.addComplain(client, ticket);
                    return "action=REJECT [RBL] "
                            + "you are permanently blocked in this server.\n\n";
                } else if (CacheBlock.contains(client, ip, sender, helo, result, recipient)) {
                    // Calcula frequencia de consultas.
                    String ticket = SPF.addQuery(ip, sender, helo, tokenSet);
                    CacheComplain.addComplain(client, ticket);
                    return "action=REJECT [RBL] "
                            + "you are permanently blocked in this server.\n\n";
                } else if (SPF.isBlacklisted(tokenSet) && CacheDefer.defer(fluxo, 1435)) {
                    // Pelo menos um identificador está listado e com atrazo programado de um dia.
                    return "action=DEFER [RBL] "
                            + "you are temporarily blocked on this server.\n\n";
                } else if (SPF.isGreylisted(tokenSet) && CacheDefer.defer(fluxo, 25)) {
                    // Pelo menos um identificador está em greylisting com atrazo programado de 10min.
                    return "action=DEFER [RBL] "
                            + "you are greylisted on this server.\n\n";
                } else if (result.equals("SOFTFAIL") && !CacheProvider.containsHELO(ip, helo) && CacheDefer.defer(fluxo, 1)) {
                    // SOFTFAIL com atrazo programado de 1min.
                    return "action=DEFER [RBL] "
                            + "you are greylisted on this server.\n\n";
                } else {
                    // Calcula frequencia de consultas.
                    String url = Core.getSpamURL();
                    String ticket = SPF.addQuery(ip, sender, helo, tokenSet);
                    return "action=PREPEND "
                            + "Received-SPFBL: " + result + " "
                            + (url == null ? "" : url) + ticket + "\n\n";
                }
            } catch (ProcessException ex) {
                if (ex.getMessage().equals("ERROR: SPF PARSE")) {
                    return "action=REJECT [SPF] "
                            + "One or more SPF records from " + sender + " "
                            + "could not be interpreted. "
                            + "Please see http://www.openspf.org/SPF_"
                            + "Record_Syntax for details.\n\n";
                } else if (ex.getMessage().equals("ERROR: RESERVED")) {
                    return "action=REJECT [SPF] "
                            + "The domain of "
                            + sender + " is a reserved TLD.\n\n";
                } else {
                    return "action=DEFER [SPF] "
                            + "A transient error occurred when "
                            + "checking SPF record from " + sender + ", "
                            + "preventing a result from being reached. "
                            + "Try again later.\n\n";
                }
            }
        }
    }

    /**
     * Processa a consulta e retorna o resultado.
     *
     * @param query a expressão da consulta.
     * @return o resultado do processamento.
     */
    protected static String processSPF(String client, String query) {
        try {
            String result = "";
            if (query.length() == 0) {
                return "ERROR: QUERY\n";
            } else {
                StringTokenizer tokenizer = new StringTokenizer(query, " ");
                String firstToken = tokenizer.nextToken();
                if (firstToken.equals("SPAM") && tokenizer.countTokens() == 1) {
                    String ticket = tokenizer.nextToken();
                    TreeSet<String> tokenSet = CacheComplain.addComplain(client, ticket);
                    if (tokenSet == null) {
                        result = "DUPLICATE COMPLAIN\n";
                    } else {
                        result = "OK " + tokenSet + "\n";
                    }
                } else if (firstToken.equals("HAM") && tokenizer.countTokens() == 1) {
                    String ticket = tokenizer.nextToken();
                    TreeSet<String> tokenSet = CacheComplain.deleteComplain(client, ticket);
                    if (tokenSet == null) {
                        result = "ALREADY REMOVED\n";
                    } else {
                        result = "OK " + tokenSet + "\n";
                    }
                } else if (firstToken.equals("REFRESH") && tokenizer.countTokens() == 1) {
                    String address = tokenizer.nextToken();
                    try {
                        if (CacheSPF.refresh(address, true)) {
                            result = "UPDATED\n";
                        } else {
                            result = "NOT LOADED\n";
                        }
                    } catch (ProcessException ex) {
                        result = ex.getMessage() + "\n";
                    }
                } else if ((firstToken.equals("SPF") && tokenizer.countTokens() >= 4)
                        || tokenizer.countTokens() == 2 || tokenizer.countTokens() == 1
                        || (firstToken.equals("CHECK") && tokenizer.countTokens() == 3)
                        || (firstToken.equals("CHECK") && tokenizer.countTokens() == 2)) {
                    try {
                        String ip;
                        String sender;
                        String helo;
                        String recipient;
                        String origem;
                        String fluxo;
                        if (firstToken.equals("SPF")) {
                            // Nova formatação de consulta.
                            ip = tokenizer.nextToken();
                            sender = tokenizer.nextToken();
                            while (!sender.endsWith("'") && tokenizer.hasMoreTokens()) {
                                sender += " " + tokenizer.nextToken();
                            }
                            helo = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : "''";
                            recipient = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : "''";
                            ip = ip.substring(1, ip.length() - 1);
                            sender = sender.substring(1, sender.length() - 1);
                            helo = helo.substring(1, helo.length() - 1);
                            recipient = recipient.substring(1, recipient.length() - 1);
                            if (sender.length() == 0) {
                                sender = null;
                            } else {
                                sender = sender.toLowerCase();
                            }
                            if (!Domain.isEmail(recipient)) {
                                recipient = null;
                            }
                        } else {
                            // Manter compatibilidade da versão antiga.
                            // Versão obsoleta.
                            if (firstToken.equals("CHECK")) {
                                ip = tokenizer.nextToken();
                            } else {
                                ip = firstToken;
                            }
                            if (tokenizer.countTokens() == 2) {
                                sender = tokenizer.nextToken().toLowerCase();
                                helo = tokenizer.nextToken().toLowerCase();
                            } else {
                                sender = null;
                                helo = tokenizer.nextToken().toLowerCase();
                            }
                            recipient = null;
                            if (ip.startsWith("'") && ip.endsWith("'")) {
                                ip = ip.substring(1, ip.length() - 1);
                            }
                            if (sender != null && sender.startsWith("'") && sender.endsWith("'")) {
                                sender = sender.substring(1, sender.length() - 1);
                            }
                            if (helo.startsWith("'") && helo.endsWith("'")) {
                                helo = helo.substring(1, helo.length() - 1);
                            }
                        }
                        if (!Subnet.isValidIP(ip)) {
                            return "INVALID\n";
                        } else if (sender != null && !Domain.isEmail(sender)) {
                            return "INVALID\n";
                        } else if (sender != null && Domain.isReserved(sender)) {
                            return "INVALID\n";
                        } else {
                            TreeSet<String> tokenSet = new TreeSet<String>();
                            ip = Subnet.normalizeIP(ip);
                            tokenSet.add(ip);
                            // Passar a acompanhar todos os 
                            // HELO quando apontados para o IP para 
                            // uma nova forma de interpretar dados.
                            if (CacheHELO.match(ip, helo)) {
                                helo = Domain.normalizeHostname(helo, true);
                                tokenSet.add(helo);
                                String ipv4 = CacheHELO.getUniqueIPv4(helo);
                                if (ipv4 != null) {
                                    // Equivalência de pilha dupla se 
                                    // IPv4 for único para o HELO.
                                    tokenSet.add(ipv4);
                                }
                                String ipv6 = CacheHELO.getUniqueIPv6(helo);
                                if (ipv6 != null) {
                                    // Equivalência de pilha dupla se 
                                    // IPv6 for único para o HELO.
                                    tokenSet.add(ipv6);
                                }
                            }
                            LinkedList<String> logList = null;
                            if (sender != null && firstToken.equals("CHECK")) {
                                int index = sender.lastIndexOf('@');
                                String domain = sender.substring(index + 1);
                                logList = new LinkedList<String>();
                                try {
                                    CacheSPF.refresh(domain, false);
                                } catch (ProcessException ex) {
                                    logList.add("Cannot refresh SPF registry: " + ex.getErrorMessage());
                                    logList.add("Using cached SPF registry.");
                                }
                            }
                            SPF spf = CacheSPF.get(sender);
                            if (spf == null) {
                                result = "NONE";
                            } else if (spf.isDefinitelyInexistent()) {
                                // O domínio foi dado como inexistente inúmeras vezes.
                                // Rejeitar e denunciar o host pois há abuso de tentativas.
                                String ticket = SPF.addQuery(ip, sender, helo, tokenSet);
                                CacheComplain.addComplain(client, ticket);
                                return "NXDOMAIN\n";
                            } else if (spf.isInexistent()) {
                                return "NXDOMAIN\n";
                            } else {
                                result = spf.getResult(ip, sender, helo, logList);
                            }
                            if (result.equals("FAIL") && !CacheWhite.containsSender(client, sender, result, recipient)) {
                                String ticket = SPF.addQuery(ip, sender, helo, tokenSet);
                                CacheComplain.addComplain(client, ticket);
                                // Retornar FAIL somente se não houver 
                                // liberação literal do remetente com FAIL.
                                return "FAIL\n";
                            } else if (result.equals("PASS") || (sender != null && CacheProvider.containsHELO(ip, helo))) {
                                // Quando fo PASS, significa que o domínio
                                // autorizou envio pelo IP, portanto o dono dele
                                // é responsavel pelas mensagens.
                                String mx = Domain.extractHost(sender, true);
                                if (CacheProvider.containsExact(mx)) {
                                    // Listar apenas o remetente se o
                                    // hostname for um provedor de e-mail.
                                    tokenSet.add(sender);
                                    origem = sender;
                                } else {
                                    // Não é um provedor então
                                    // o MX deve ser listado.
                                    tokenSet.add(mx);
                                    origem = mx;
                                }
                                fluxo = origem + ">" + recipient;
                            } else if (CacheHELO.match(ip, helo)) {
                                String dominio = Domain.extractDomain(helo, true);
                                origem = sender + ">" + dominio.substring(1);
                                fluxo = origem + ">" + recipient;
                            } else {
                                origem = sender + ">" + ip;
                                fluxo = origem + ">" + recipient;
                            }
                            if (firstToken.equals("CHECK")) {
                                result = "\nSPF resolution results:\n";
                                if (logList == null || logList.isEmpty()) {
                                    result += "   NONE\n";
                                } else {
                                    for (String log : logList) {
                                        result += "   " + log + "\n";
                                    }
                                }
                                String block = CacheBlock.find(client, ip, sender, helo, query, recipient);
                                if (block != null) {
                                    result += "\nFirst BLOCK match: " + block + "\n";
                                }
                                result += "\n";
                                result += "Considered identifiers and status:\n";
                                tokenSet = expandTokenSet(tokenSet);
                                TreeMap<String,Distribution> distributionMap = CacheDistribution.getMap(tokenSet);
                                for (String token : tokenSet) {
                                    float probability;
                                    Status status;
//                                    String frequency;
                                    if (distributionMap.containsKey(token)) {
                                        Distribution distribution = distributionMap.get(token);
                                        probability = distribution.getSpamProbability(token);
                                        status = distribution.getStatus(token);
//                                        frequency = distribution.getFrequencyLiteral();
                                    } else {
                                        probability = 0.0f;
                                        status = SPF.Status.WHITE;
//                                        frequency = "UNDEFINED";
                                    }
                                    result += "   " + token
//                                            + " " + frequency
                                            + " " + status.name() + " "
                                            + Server.DECIMAL_FORMAT.format(probability) + "\n";
                                }
                                result += "\n";
                                return result;
                            } else if (CacheWhite.contains(client, ip, sender, helo, result, recipient)) {
                                // Calcula frequencia de consultas.
                                String url = Core.getSpamURL();
                                String ticket = SPF.addQuery(ip, sender, helo, tokenSet);
                                return result + " " + (url == null ? "" : url) + ticket + "\n";
                            } else if (CacheTrap.contains(client, recipient)) {
                                // Calcula frequencia de consultas.
                                String ticket = SPF.addQuery(ip, sender, helo, tokenSet);
                                CacheComplain.addComplain(client, ticket);
                                return "SPAMTRAP\n";
                            } else if (SPF.isBlocked(tokenSet)) {
                                 // Calcula frequencia de consultas.
                                String ticket = SPF.addQuery(ip, sender, helo, tokenSet);
                                CacheComplain.addComplain(client, ticket);
                                return "BLOCKED\n";
                            } else if (CacheBlock.contains(client, ip, sender, helo, result, recipient)) {
                                // Calcula frequencia de consultas.
                                String ticket = SPF.addQuery(ip, sender, helo, tokenSet);
                                CacheComplain.addComplain(client, ticket);
                                return "BLOCKED\n";
                            } else if (SPF.isBlacklisted(tokenSet) && CacheDefer.defer(fluxo, 1435)) {
                                // Pelo menos um identificador do conjunto está em lista negra com atrazo de 1 dia.
                                return "LISTED\n";
                            } else if (SPF.isGreylisted(tokenSet) && CacheDefer.defer(fluxo, 25)) {
                                // Pelo menos um identificador do conjunto está em greylisting com atrazo de 10min.
                                return "GREYLIST\n";
                            } else if (result.equals("SOFTFAIL") && !CacheProvider.containsHELO(ip, helo) && CacheDefer.defer(fluxo, 1)) {
                                // SOFTFAIL com atrazo de 1min.
                                return "GREYLIST\n";
                            } else {
                                // Calcula frequencia de consultas.
                                String url = Core.getSpamURL();
                                String ticket = SPF.addQuery(ip, sender, helo, tokenSet);
                                return result + " " + (url == null ? "" : url) + ticket + "\n";
                            }
                        }
                    } catch (ProcessException ex) {
                        if (ex.getMessage().equals("ERROR: HOST NOT FOUND")) {
                            return "NXDOMAIN\n";
                        } else {
                            throw ex;
                        }
                    }
                } else {
                    return "ERROR: QUERY\n";
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

    public static String createTicket(TreeSet<String> tokenSet) throws ProcessException {
        String ticket = Server.getNewTicketDate();
        for (String token : tokenSet) {
            ticket += " " + token;
        }
        return Server.encrypt(ticket);
    }

    private static Date getTicketDate(String date) throws ProcessException {
        try {
            return Server.parseTicketDate(date);
        } catch (ParseException ex) {
            throw new ProcessException("ERROR: INVALID TICKET", ex);
        }
    }
    
    private static TreeSet<String> expandTokenSet(
            TreeSet<String> tokenSet) {
        TreeSet<String> expandedSet = new TreeSet<String>();
        for (String token : tokenSet) {
            if (token != null) {
                expandedSet.add(token);
                boolean expand;
                if (token.startsWith("@") && Domain.isHostname(token.substring(1))) {
                    token = '.' + token.substring(1);
                    expand = true;
                } else if (token.startsWith(".") && Domain.isHostname(token.substring(1))) {
                    expand = true;
                } else if (!token.startsWith(".") && Domain.isHostname(token)) {
                    token = '.' + token;
                    expand = true;
                } else {
                    expand = false;
                }
                if (expand) {
                    try {
                        String dominio = Domain.extractDomain(token, true);
                        String subdominio = Domain.extractHost(token, true);
                        while (!subdominio.equals(dominio)) {
                            expandedSet.add(subdominio);
                            int index = subdominio.indexOf('.', 1);
                            subdominio = subdominio.substring(index);
                        }
                        expandedSet.add(dominio);
                    } catch (ProcessException ex) {
                        expandedSet.add(token);
                        Server.logError(ex);
                    }
                }
            }
        }
        return expandedSet;
    }

    public static String addQuery(
            String ip, String sender, String helo,
            TreeSet<String> tokenSet) throws ProcessException {
        long time = System.currentTimeMillis();
        for (String token : expandTokenSet(tokenSet)) {
            Distribution distribution = CacheDistribution.get(token, true);
            if (distribution != null) {
                distribution.addQuery();
            }
        }
        String ticket = SPF.createTicket(tokenSet);
        Server.logTicket(time,
//                ip, sender, helo,
                tokenSet, ticket);
        return ticket;
    }

    public static long getComplainTTL(String token) {
        Distribution distribution = CacheDistribution.get(token, false);
        if (distribution == null) {
            // Distribuição não encontrada.
            // Considerar que não está listado.
            return 0;
        } else {
            // Transformar em segundos.
            return distribution.getComplainTTL() / 1000;
        }
    }

    public static boolean isBlacklisted(String token) {
        Distribution distribution = CacheDistribution.get(token, true);
//        if (distribution == null) {
//            // Distribuição não encontrada.
//            // Considerar que não está listado.
//            return false;
//        } else {
            return distribution.isBlacklisted(token);
//        }
    }

    public static boolean isGreylisted(String token) {
        Distribution distribution = CacheDistribution.get(token, false);
        if (distribution == null) {
            // Distribuição não encontrada.
            // Considerar que não está listado.
            return false;
        } else {
            return distribution.isGreylisted(token);
        }
    }

    public static boolean isBlocked(String token) {
        Distribution distribution = CacheDistribution.get(token, true);
//        if (distribution == null) {
//            // Distribuição não encontrada.
//            // Considerar que não está listado.
//            return false;
//        } else {
            return distribution.isBlocked(token);
//        }
    }

    private static boolean isGreylisted
            (TreeSet<String> tokenSet
            ) throws ProcessException {
        boolean greylisted = false;
        for (String token : expandTokenSet(tokenSet)) {
            if (isGreylisted(token)) {
                greylisted = true;
            }
        }
        return greylisted;
    }

    private static boolean isBlacklisted(
            TreeSet<String> tokenSet
            ) throws ProcessException {
        boolean blacklisted = false;
        for (String token : expandTokenSet(tokenSet)) {
            if (isBlacklisted(token)) {
                blacklisted = true;
            }
        }
        return blacklisted;
    }

    private static boolean isBlocked(
            TreeSet<String> tokenSet
            ) throws ProcessException {
        boolean blocked = false;
        for (String token : expandTokenSet(tokenSet)) {
            if (isBlocked(token)) {
                blocked = true;
            }
        }
        return blocked;
    }

    /**
     * Enumeração do status da distribuição.
     */
    public enum Status implements Serializable {

        WHITE, // Whitelisted
        GRAY, // Graylisted
        BLACK, // Blacklisted
        BLOCK; // Blocked
    }
    /**
     * Constantes que determinam os limiares de listagem.
     */
    private static final float LIMIAR1 = 0.25f;
    private static final float LIMIAR2 = 0.50f;
    private static final float LIMIAR3 = 0.75f;

    /**
     * Classe que representa a distribuição binomial entre SPAM e HAM.
     */
    public static final class Distribution implements Serializable {

        private static final long serialVersionUID = 1L;
        private int complain; // Quantidade total de reclamações.
        private long lastQuery; // Última consulta à distribuição.
        private long lastComplain; // Última denúncia à distribuição.
        private Status status; // Status atual da distribuição.
        private NormalDistribution frequency = null; // Frequência média em segundos.
        
        public Distribution() {
            reset();
        }
        
        public void reset() {
            complain = 0;
            lastQuery = 0;
            lastComplain = 0;
            status = Status.WHITE;
            frequency = null;
            CacheDistribution.CHANGED = true;
        }

        public boolean isExpired7() {
            return System.currentTimeMillis() - lastQuery > 604800000;
        }

        public boolean isExpired14() {
            return System.currentTimeMillis() - lastQuery > 604800000 * 2;
        }

        public long getComplainTTL() {
            long ttl = lastComplain + 604800000 - System.currentTimeMillis();
            if (ttl < 0) {
                return 0;
            } else {
                return ttl;
            }
        }

        public boolean clear() {
            if (complain == 0) {
                return false;
            } else {
                complain = 0;
                status = Status.WHITE;
                CacheDistribution.CHANGED = true;
                return true;
            }
        }

        public boolean hasFrequency() {
            return frequency != null;
        }

        public boolean hasLastQuery() {
            return lastQuery > 0;
        }

        public String getFrequencyLiteral() {
            if (hasFrequency()) {
                return frequency.toStringInt() + "s";
            } else {
                return "UNDEFINED";
            }
        }

        private float getInterval(boolean refresh) {
            long currentTime = System.currentTimeMillis();
            float interval;
            if (lastQuery == 0) {
                interval = 0;
            } else {
                interval = (float) (currentTime - lastQuery) / (float) 1000;
            }
            if (refresh) {
                lastQuery = currentTime;
                CacheDistribution.CHANGED = true;
            }
            return interval;
        }

        public void addQuery() {
            float interval = getInterval(true);
            if (interval == 0.0f) {
                // Se não houver intervalo definido,
                // considerar frequência nula.
                frequency = null;
            } else if (frequency == null) {
                frequency = new NormalDistribution(interval);
            } else {
                frequency.addElement(interval);
            }
        }

//        public float getMinSpamProbability() {
//            return getSpamProbability()[0];
//        }
//
//        public float getMaxSpamProbability() {
//            return getSpamProbability()[2];
//        }

//        private float[] getSpamProbability() {
//            float[] probability = new float[3];
//            if (frequency == null) {
//                // Se não houver frequência definida,
//                // considerar probabilidade zero
//                // pela impossibilidade de cálculo.
//                return probability;
//            } else if (complain < 5) {
//                // Se a quantida total de reclamações for
//                // menor que cinco, considerar probabilidade zero
//                // por conta na baixa precisão do cálculo.
//                return probability;
//            } else if (frequency.getAverage() == 0.0d) {
//                // Impossível calcular por conta da divisão por zero.
//                // Considerar probabilidade zero.
//                return probability;
//            } else {
//                // Estimativa máxima do total de mensagens por
//                // semana calculado pela amostragem mais recente.
//                double semana = 60 * 60 * 24 * 7;
//                float probabilityMin = (float) complain / (float) (semana / frequency.getMinimum());
//                if (probabilityMin < 0) {
//                    probabilityMin = 0.0f;
//                } else if (probabilityMin > 1.0) {
//                    probabilityMin = 1.0f;
//                }
//                float probabilityAvg = (float) complain / (float) (semana / frequency.getAverage());
//                if (probabilityAvg < 0) {
//                    probabilityAvg = 0.0f;
//                } else if (probabilityAvg > 1.0) {
//                    probabilityAvg = 1.0f;
//                }
//                float probabilityMax = (float) complain / (float) (semana / frequency.getMaximum());
//                if (probabilityMax < 0) {
//                    probabilityMax = 0.0f;
//                } else if (probabilityMax > 1.0) {
//                    probabilityMax = 1.0f;
//                }
//                probability[0] = probabilityMin;
//                probability[1] = probabilityAvg;
//                probability[2] = probabilityMax;
//                return probability;
//            }
//        }
        
        public float getSpamProbability(String token) {
            int[] binomial = getBinomial();
            if (token != null) {
                for (Peer peer : Peer.getSet()) {
                    Binomial peerBinomial = peer.getBinomial(token);
                    if (peerBinomial != null) {
                        binomial[0] += peerBinomial.getHAM();
                        binomial[1] += peerBinomial.getSPAM();
                    }
                }
            }
            if (binomial[1] < 3) {
                return 0.0f;
            } else {
                int total = binomial[0] + binomial[1];
                return (float) binomial[1] / (float) total;
            }
        }

//        /**
//         * Máquina de estados para listar em um pico e retirar a listagem
//         * somente quando o total cair consideravelmente após este pico.
//         *
//         * @return o status atual da distribuição.
//         */
//        public Status getStatus(String token) {
//            if (status == Status.BLOCK) {
//                float max = getMaxSpamProbability();
//                if (max < LIMIAR1) {
//                    status = Status.GRAY;
//                    CacheBlock.dropExact(token);
//                }
//            } else {
//                Status statusOld = status;
//                float[] probability = getSpamProbability();
//                float min = probability[0];
//                float max = probability[2];
//                if (min > LIMIAR2 && max > LIMIAR3 &&
//                        complain > 7 && !Subnet.isValidIP(token)) {
//                    // Condição especial que bloqueia
//                    // definitivamente o responsável.
//                    status = Status.BLOCK;
//                    CacheBlock.addExact(token);
//                    Peer.sendToAll(token);
//                } else if (max == 0.0f) {
//                    status = Status.WHITE;
//                } else if (min > LIMIAR1) {
//                    status = Status.BLACK;
//                } else if (statusOld == Status.GRAY && min > LIMIAR1) {
//                    status = Status.BLACK;
//                } else if (statusOld == Status.BLACK && max < LIMIAR1) {
//                    status = Status.GRAY;
//                }
//            }
//            return status;
//        }
        
        /**
         * Máquina de estados para listar em um pico e retirar a listagem
         * somente quando o total cair consideravelmente após este pico.
         *
         * @return o status atual da distribuição.
         */
        public Status getStatus(String token) {
            Status statusOld = status;
            float probability = getSpamProbability(token);
            if (probability > LIMIAR3) {
                status = Subnet.isValidIP(token) ? Status.BLACK : Status.BLOCK;
            } else if (probability > LIMIAR2) {
                status = Status.BLACK;
            } else if (probability > LIMIAR1) {
                status = Status.GRAY;
            } else if (probability == 0.0f) {
                status = Status.WHITE;
            } else if (statusOld == Status.GRAY && probability > LIMIAR1) {
                status = Status.BLACK;
            } else if (statusOld == Status.BLACK && probability < LIMIAR1) {
                status = Status.GRAY;
            }
            return status;
        }

        /**
         * Verifica se o estado atual da distribuição é greylisted.
         *
         * @param query se contabiliza uma consulta com a verificação.
         * @return verdadeiro se o estado atual da distribuição é greylisted.
         */
        public boolean isBlacklisted(String token) {
            return getStatus(token) == Status.BLACK;
        }

        public boolean isGreylisted(String token) {
            return getStatus(token) == Status.GRAY;
        }

        public boolean isBlocked(String token) {
            return getStatus(token) == Status.BLOCK;
        }

        public synchronized boolean removeSpam() {
            if (complain > 0) {
                complain--;
                CacheDistribution.CHANGED = true;
                return true;
            } else {
                return false;
            }
        }

        public synchronized boolean addSpam() {
            if (complain < Integer.MAX_VALUE) {
                complain++;
                lastComplain = System.currentTimeMillis();
                CacheDistribution.CHANGED = true;
                return true;
            } else {
                return false;
            }
        }
        
        public synchronized int[] getBinomial() {
            if (frequency == null) {
                return new int[2];
            } else if (frequency.getMinimum() > 0.0d) {
                int[] result = new int[2];
                double semana = 60 * 60 * 24 * 7;
                int total = (int) (semana / frequency.getMinimum());
                if (total < complain) {
                    total = complain;
                }
                int ham = total - complain;
                int spam = complain;
                result[0] = ham;
                result[1] = spam;
                return result;
            } else {
                return new int[2];
            }
        }

        @Override
        public String toString() {
            return Float.toString(getSpamProbability(null));
        }
    }
}
