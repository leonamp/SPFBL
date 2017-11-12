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
 * along with SPFBL. If not, see <http://www.gnu.org/licenses/>.
 */
package net.spfbl.spf;

import com.sun.mail.util.MailConnectException;
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
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.NavigableMap;
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.mail.Message;
import javax.mail.SendFailedException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.naming.CommunicationException;
import javax.naming.InvalidNameException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.ServiceUnavailableException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.InvalidAttributeIdentifierException;
import net.spfbl.core.Action;
import net.spfbl.core.Analise;
import net.spfbl.core.Client;
import net.spfbl.data.Block;
import net.spfbl.core.Defer;
import net.spfbl.data.Ignore;
import net.spfbl.data.NoReply;
import net.spfbl.core.Peer;
import net.spfbl.data.Provider;
import net.spfbl.core.Reverse;
import net.spfbl.core.User;
import net.spfbl.core.User.Query;
import net.spfbl.data.Generic;
import net.spfbl.data.Trap;
import net.spfbl.data.White;
import net.spfbl.http.ServerHTTP;
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
    private static LinkedList<String> getRegistrySPF(
            String hostname,
            boolean bgWhenUnavailable
    ) throws ProcessException {
        LinkedList<String> registryList = new LinkedList<>();
        try {
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
            if (registryList.isEmpty()) {
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
        LinkedList<String> midleList = new LinkedList<>();
        LinkedList<String> errorList = new LinkedList<>();
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
        this.queries = 0;
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
            this.mechanismList = new ArrayList<>();
            this.all = null;
            this.redirect = null;
            this.explanation = null;
            this.error = false;
            CacheSPF.CHANGED = true;
            this.nxdomain = 0;
            updateLastRefresh();
            Server.logLookupSPF(time, hostname, "NO REGISTRY");
        } else {
            ArrayList<Mechanism> mechanismListIP = new ArrayList<>();
            ArrayList<Mechanism> mechanismListDNS = new ArrayList<>();
            ArrayList<Mechanism> mechanismListInclude = new ArrayList<>();
            ArrayList<Mechanism> mechanismListPTR = new ArrayList<>();
            TreeSet<String> visitedTokens = new TreeSet<>();
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
            ArrayList<Mechanism> mechanismListLocal = new ArrayList<>();
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
        if (helo != null) {
            hostname = hostname.replace("%{h}", helo.startsWith(".") ? helo.substring(1) : helo);
        }
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
        long expiredTime = (System.currentTimeMillis() - lastRefresh) / Server.DAY_TIME;
        return expiredTime > REFRESH_TIME;
    }
    
    /**
     * Verifica se o registro atual expirou.
     *
     * @return verdadeiro se o registro atual expirou.
     */
    public boolean isRegistryExpired7() {
        long expiredTime = (System.currentTimeMillis() - lastRefresh) / Server.DAY_TIME * 7;
        return expiredTime > REFRESH_TIME;
    }
    
    /**
     * Verifica se o registro atual expirou.
     *
     * @return verdadeiro se o registro atual expirou.
     */
    public boolean isRegistryExpired14() {
        long expiredTime = (int) (System.currentTimeMillis() - lastRefresh) / Server.DAY_TIME * 14;
        return expiredTime > REFRESH_TIME;
    }

    /**
     * Retorna o resultado SPF para um IP especifico.
     *
     * @param ip o IP a ser verificado.
     * @return o resultado SPF para um IP especifico.
     * @throws ProcessException se houver falha no processamento.
     */
    public String getResult(
            String ip,
            String sender,
            String helo,
            LinkedList<String> logList
    ) throws ProcessException {
        Qualifier qualifier = getQualifier(
                System.currentTimeMillis(),
                ip, sender, helo, 0,
                new TreeSet<>(),
                logList
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
    private Qualifier getQualifier(
            long time, String ip, String sender, String helo,
            int deep, TreeSet<String> hostVisitedSet,
            LinkedList<String> logList
    ) throws ProcessException {
        if (deep > 10) {
            return null; // Evita excesso de consultas.
        } else if (hostVisitedSet.contains(getHostname())) {
            return null; // Evita looping infinito.
        } else if (mechanismList == null) {
            throw new ProcessException("HOST NOT FOUND");
        } else if (System.currentTimeMillis() - time > 5000) {
            return Qualifier.SOFTFAIL; // Evita excesso de latência da resposta.
        } else {
            boolean hostNotFound = false;
            hostVisitedSet.add(getHostname());
            for (Mechanism mechanism : mechanismList) {
                if (mechanism instanceof MechanismInclude) {
                    try {
                        MechanismInclude include = (MechanismInclude) mechanism;
                        Qualifier qualifier = include.getQualifierSPF(
                                time, ip, sender, helo, deep + 1,
                                hostVisitedSet, logList
                        );
                        if (qualifier == null) {
                            // Nenhum qualificador foi definido
                            // então continuar busca.
                        } else {
                            return qualifier;
                        }
                    } catch (ProcessException ex) {
                        if (ex.getMessage().equals("HOST NOT FOUND")) {
                            // Não foi possível fazer o include.
                            // O hostname mencionado não existe.
                            // Continuar a verificação dos demais 
                            // mecanismos antes de efetivar o erro.
                            hostNotFound = true;
                        } else {
                            throw ex;
                        }
                    }
                } else if (mechanism instanceof MechanismPTR) {
                    if (mechanism.match(ip, sender, helo)) {
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
                SPF spf = CacheSPF.get(redirect);
                if (spf == null) {
                    logRedirect(redirect, "NOT FOUND", logList);
                    return null;
                } else {
                    Qualifier qualifier = spf.getQualifier(
                            time, ip, sender, helo, 0,
                            hostVisitedSet, logList
                    );
                    logRedirect(redirect, qualifier, logList);
                    return qualifier;
                }
            } else if (error || hostNotFound) {
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
    public enum Qualifier {

        PASS("Pass"),
        FAIL("Fail"),
        SOFTFAIL("SoftFail"),
        NEUTRAL("Neutral");
        private final String description;

        private Qualifier(String description) {
            this.description = description;
        }
        
        public static Qualifier get(String name) {
            try {
                return valueOf(name);
            } catch (Exception ex) {
                return null;
            }
        }
        
        public static String name(Qualifier qualifier) {
            if (qualifier == null) {
                return null;
            } else {
                return qualifier.name();
            }
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
        private final ArrayList<Mechanism> mechanismList = new ArrayList<>();
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
                TreeSet<String> resultSet = new TreeSet<>();
                try {
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
                } catch (CommunicationException ex) {
                    Server.logMecanismA(time, "A " + expression, "TIMEOUT");
                } catch (ServiceUnavailableException ex) {
                    Server.logMecanismA(time, "A " + expression, "SERVFAIL");
                } catch (NameNotFoundException ex) {
                    Server.logMecanismA(time, "A " + expression, "NOT FOUND");
                } catch (InvalidAttributeIdentifierException ex) {
                    Server.logMecanismA(time, "A " + expression, "NOT FOUND");
                } catch (InvalidNameException ex) {
                    Server.logMecanismA(time, "A " + expression, "INVALID");
                } catch (NamingException ex) {
                    Server.logMecanismA(time, "A " + expression, "ERROR " + ex.getClass() + " " + ex.getMessage());
                }
                try {
                    Attributes attributes = Server.getAttributesDNS(
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
                } catch (CommunicationException ex) {
                    Server.logMecanismA(time, "AAAA " + expression, "TIMEOUT");
                } catch (ServiceUnavailableException ex) {
                    Server.logMecanismA(time, "AAAA " + expression, "SERVFAIL");
                } catch (NameNotFoundException ex) {
                    Server.logMecanismA(time, "AAAA " + expression, "NOT FOUND");
                } catch (InvalidAttributeIdentifierException ex) {
                    Server.logMecanismA(time, "AAAA " + expression, "NOT FOUND");
                } catch (InvalidNameException ex) {
                    Server.logMecanismA(time, "AAAA " + expression, "INVALID");
                } catch (NamingException ex) {
                    Server.logMecanismA(time, "AAAA " + expression, "ERROR " + ex.getClass() + " " + ex.getMessage());
                }
                Server.logMecanismA(time, expression, resultSet.toString());
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
        private final ArrayList<Mechanism> mechanismList = new ArrayList<>();
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
                mechanismList.clear();
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
                    TreeSet<String> resultSet = new TreeSet<>();
                    Attributes attributesMX = Server.getAttributesDNS(
                            hostname, new String[]{"MX"});
                    Attribute attributeMX = attributesMX.get("MX");
                    if (attributeMX == null) {
                        Attributes attributesA = Server.getAttributesDNS(
                                hostname, new String[]{"A"});
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
                                hostname, new String[]{"AAAA"});
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
                    } else {
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
                                } catch (NamingException ex) {
                                    // Endereço não encontrado.
                                }
                                try {
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
                            }
                        }
                    }
                    Server.logMecanismMX(time, expression, resultSet.toString());
                } catch (CommunicationException ex) {
                    Server.logMecanismMX(time, expression, "TIMEOUT");
                } catch (ServiceUnavailableException ex) {
                    Server.logMecanismMX(time, expression, "SERVFAIL");
                } catch (NameNotFoundException ex) {
                    Server.logMecanismMX(time, expression, "NOT FOUND");
                } catch (InvalidAttributeIdentifierException ex) {
                    Server.logMecanismMX(time, expression, "NOT FOUND");
                } catch (InvalidNameException ex) {
                    Server.logMecanismA(time, expression, "INVALID");
                } catch (NamingException ex) {
                    Server.logMecanismMX(time, expression, "ERROR " + ex.getClass() + " " + ex.getMessage());
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
            Reverse reverse = Reverse.get(ip);
            if (reverse == null) {
                return false;
            } else {
                for (String address : reverse.getAddressSet()) {
                    if (address.endsWith(hostname)) {
                        return true;
                    }
                }
                return false;
            }
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
                Server.getAttributesDNS(hostname, new String[]{"A"});
                Server.logMecanismA(time, hostname, "EXISTS");
                return true;
            } catch (CommunicationException ex) {
                Server.logMecanismA(time, hostname, "TIMEOUT");
                return false;
            } catch (ServiceUnavailableException ex) {
                Server.logMecanismA(time, hostname, "SERVFAIL");
                return false;
            } catch (NameNotFoundException ex) {
                Server.logMecanismA(time, hostname, "NOT FOUND");
                return false;
            } catch (InvalidAttributeIdentifierException ex) {
                Server.logMecanismA(time, hostname, "NOT FOUND");
                return false;
            } catch (InvalidNameException ex) {
                Server.logMecanismA(time, hostname, "INVALID");
                return false;
            } catch (NamingException ex) {
                Server.logMecanismA(time, hostname, "ERROR " + ex.getClass() + " " + ex.getMessage());
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
                long time, String ip, String sender, String helo,
                int deep, TreeSet<String> hostVisitedSet,
                LinkedList<String> logList) throws ProcessException {
            String hostname = getHostname(ip, sender, helo);
            SPF spf = CacheSPF.get(hostname);
            if (spf == null) {
                return null;
            } else {
                return spf.getQualifier(
                        time,
                        ip, sender, helo, deep,
                        hostVisitedSet, logList
                );
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
        private static final HashMap<String,SPF> MAP = new HashMap<>();
        /**
         * O próximo registro SPF que deve ser atualizado.
         */
        private static SPF spfRefresh = null;
        /**
         * Flag que indica se o cache foi modificado.
         */
        private static boolean CHANGED = false;
        
        private static boolean isChanged() {
            return CHANGED;
        }
        
        private static void setNotChanged() {
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
            TreeSet<String> keySet = new TreeSet<>();
            keySet.addAll(MAP.keySet());
            return keySet;
        }
        
        private static synchronized HashMap<String,SPF> getMap() {
            HashMap<String,SPF> map = new HashMap<>();
            map.putAll(MAP);
            return map;
        }
        
        private static SPF getExact(String host) {
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
                    if (load) {
                        spf = new SPF(host);
                        add(spf);
                        return true;
                    } else {
                        return false;
                    }
                } else {
                    spf.refresh(load, false);
                    return true;
                }
            }
        }
        
        private static SPF get(String address) throws ProcessException {
            return get(address, false);
        }

        /**
         * Retorna o registro SPF do e-mail.
         *
         * @param address o endereço de e-mail que deve ser consultado.
         * @return o registro SPF, se for encontrado.
         * @throws ProcessException se houver falha no processamento.
         */
        private static SPF get(String address, boolean refresh) throws ProcessException {
            String host = Domain.extractHost(address, false);
            if (host == null) {
                return null;
            } else {
                SPF spf = getExact(host);
                if (spf == null) {
                    spf = new SPF(host);
                    add(spf);
                } else if (refresh || spf.isRegistryExpired()) {
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
                    try (FileOutputStream outputStream = new FileOutputStream(file)) {
                        SerializationUtils.serialize(map, outputStream);
                        setNotChanged();
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
                    try (FileInputStream fileInputStream = new FileInputStream(file)) {
                        map = SerializationUtils.deserialize(fileInputStream);
                    }
                    for (String key : map.keySet()) {
                        Object value = map.get(key);
                        if (value instanceof SPF) {
                            SPF spf = (SPF) value;
                            if (!spf.isRegistryExpired14()) {
                                putExact(key, spf);
                            }
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
                    if (ex.getMessage().equals("HOST NOT FOUND")) {
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
    
    public static Qualifier getQualifier(String ip, String sender, String helo, boolean refresh) {
        try {
            SPF spf = CacheSPF.get(sender, refresh);
            return spf.getQualifier(
                    System.currentTimeMillis(),
                    ip, sender, helo, 0,
                    new TreeSet<>(), null
            );
        } catch (ProcessException ex) {
            return null;
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
    
    public static boolean addComplain(String ip) throws ProcessException {
        if (ip == null) {
            return false;
        } else if (Subnet.isValidIP(ip)) {
            ip = Subnet.normalizeIP(ip);
            Distribution distribution = CacheDistribution.get(ip, true);
            if (Ignore.contains(ip)) {
                return false;
            } else {
                distribution.addSpam(Server.getNewUniqueTime());
                Peer.sendToAll(ip, distribution);
                return true;
            }
        } else {
            return false;
        }
    }
    
    /**
     * Adiciona uma nova reclamação de SPAM.
     *
     * @param ticket o ticket da mensagem original.
     * @throws ProcessException se houver falha no processamento do ticket.
     */
    public static TreeSet<String> addComplain(
            String origin,
            String ticket
    ) throws ProcessException {
        if (ticket == null) {
            return null;
        } else {
            long time = System.currentTimeMillis();
            TreeSet<String> tokenSet = new TreeSet<>();
            TreeSet<String> blackSet = new TreeSet<>();
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
                String recipient = null;
                while (tokenizer.hasMoreTokens()) {
                    String token = tokenizer.nextToken();
                    if (isValidReputation(token)) {
                        tokenSet.add(token);
                        if (builder.length() > 0) {
                            builder.append(' ');
                        }
                        builder.append(token);
                    } else if (token.startsWith(">") && Domain.isValidEmail(token.substring(1))) {
                        recipient = token.substring(1);
                    }
                }
                for (String key : expandTokenSet(tokenSet)) {
                    Distribution distribution = CacheDistribution.get(key, true);
                    if (Ignore.contains(key)) {
                        distribution.addHam(date.getTime());
                    } else if (distribution.addSpam(date.getTime())) {
                        distribution.getStatus(key);
                        Peer.sendToAll(key, distribution);
                    }
                    blackSet.add(key);
                }
                Server.log(time, Core.Level.DEBUG, "CMPLN", origin, ticket, blackSet, recipient);
                return blackSet;
            }
        }
    }
    
    public static long getDateTicket(
            String ticket) throws ProcessException {
        try {
            byte[] byteArray = Server.decryptToByteArrayURLSafe(ticket);
            if (byteArray.length > 8) {
                long date = byteArray[7] & 0xFF;
                date <<= 8;
                date += byteArray[6] & 0xFF;
                date <<= 8;
                date += byteArray[5] & 0xFF;
                date <<= 8;
                date += byteArray[4] & 0xFF;
                date <<= 8;
                date += byteArray[3] & 0xFF;
                date <<= 8;
                date += byteArray[2] & 0xFF;
                date <<= 8;
                date += byteArray[1] & 0xFF;
                date <<= 8;
                date += byteArray[0] & 0xFF;
                return date;
            } else {
                return 0;
            }
        } catch (ProcessException ex) {
            return 0;
        }
    }
    
    private static String getHoldStatus(
            Client client,
            long time,
            User.Query query
    ) {
        if (query == null) {
            return "HOLD";
        } else if (query.isWhiteKey()) {
            SPF.setHam(time, query.getTokenSet());
            query.setResult("WHITE");
            return "WHITE";
        } else if (query.isBlockKey()) {
            SPF.setSpam(time, query.getTokenSet());
            query.setResult("BLOCK");
            return "REMOVE";
        } else if (query.isInexistent(client)) {
            query.blockKey(time);
            query.setResult("BLOCK");
            return "BLOCK";
        } else if (User.isExpiredHOLD(time)) {
            Server.logTrace("query expired.");
            if (query.isRecipientAdvised()) {
                query.blockKey(time);
                query.setResult("BLOCK");
            } else if (query.isSenderAdvised() && query.isSenderRed()) {
                query.blockKey(time);
                query.setResult("BLOCK");
            } else {
                query.setResult("REJECT");
            }
            return "REMOVE";
        } else if (query.isAnyLinkBLOCK()) {
            Action action = client == null ? Action.REJECT : client.getActionBLOCK();
            if (action == Action.FLAG) {
                query.setResult("FLAG");
                return "FLAG";
            } else if (action == Action.HOLD) {
                query.setResult("HOLD");
                return "HOLD";
            } else {
                query.blockKey(time);
                query.setResult("BLOCK");
                return "REMOVE";
            }
        } else if (!query.hasMessageID() || query.isInvalidDate(time) || query.hasMiscellaneousSymbols() || query.hasTokenRed() || query.isAnyLinkRED() || query.isBlock()) {
            Action action = client == null ? Action.FLAG : client.getActionRED();
            if (action == Action.FLAG) {
                query.setResult("FLAG");
                return "FLAG";
            } else if (action == Action.HOLD) {
                query.setResult("HOLD");
                return "HOLD";
            } else {
                SPF.setSpam(time, query.getTokenSet());
                query.setResult("REJECT");
                return "REMOVE";
            }
        } else if (query.hasTokenYellow()) {
            long lifeTimeMin = (System.currentTimeMillis() - time) / 1000 / 60;
            if (lifeTimeMin < Core.getDeferTimeYELLOW()) {
                return "HOLD";
            } else {
                SPF.setHam(time, query.getTokenSet());
                query.setResult("ACCEPT");
                return "ACCEPT";
            }
        } else if (query.isSoftfail()) {
            long lifeTimeMin = (System.currentTimeMillis() - time) / 1000 / 60;
            if (lifeTimeMin < Core.getDeferTimeSOFTFAIL()) {
                return "HOLD";
            } else {
                SPF.setHam(time, query.getTokenSet());
                query.setResult("ACCEPT");
                return "ACCEPT";
            }
        } else if (query.isGreen()) {
            SPF.setHam(time, query.getTokenSet());
            query.setResult("ACCEPT");
            return "ACCEPT";
        } else if (query.isResult("HOLD")) {
            return "HOLD";
        } else {
            return "REMOVE";
        }
    }
    
    private static String getHoldStatus(
            Client client,
            String ticket,
            LinkedList<User> userList
    ) {
        if (ticket == null) {
            return "INVALID";
        } else {
            try {
                byte[] byteArray = Server.decryptToByteArrayURLSafe(ticket);
                if (byteArray.length > 8) {
                    long date = byteArray[7] & 0xFF;
                    date <<= 8;
                    date += byteArray[6] & 0xFF;
                    date <<= 8;
                    date += byteArray[5] & 0xFF;
                    date <<= 8;
                    date += byteArray[4] & 0xFF;
                    date <<= 8;
                    date += byteArray[3] & 0xFF;
                    date <<= 8;
                    date += byteArray[2] & 0xFF;
                    date <<= 8;
                    date += byteArray[1] & 0xFF;
                    date <<= 8;
                    date += byteArray[0] & 0xFF;
                    String query = Core.decodeHuffman(byteArray, 8);
                    StringTokenizer tokenizer = new StringTokenizer(query, " ");
                    String command = tokenizer.nextToken();
                    if (command.equals("spam")) {
                        User user = null;
                        while (tokenizer.hasMoreTokens()) {
                            String token = tokenizer.nextToken();
                            if (token.endsWith(":") && Domain.isValidEmail(token.substring(0,token.length()-1))) {
                                user = User.get(token.substring(0,token.length()-1));
                            }
                        }
                        if (user == null) {
                            return "REMOVE";
                        } else {
                            userList.add(user);
                            User.Query userQuery = user.getQuerySafe(date);
                            if (userQuery == null) {
                                if (System.currentTimeMillis() - date > 604800000) {
                                    return "REMOVE";
                                } else {
                                    return "HOLD";
                                }
                            } else {
                                String result = getHoldStatus(client, date, userQuery);
                                User.storeDB(date, userQuery);
                                return result;
                            }
                        }
                    } else {
                        return "INVALID";
                    }
                } else {
                    return "INVALID";
                }
            } catch (ProcessException ex) {
                Server.logError(ex);
                return "ERROR";
            }
        }
    }
    
    public static TreeSet<String> addComplainURLSafe(
            String origin,
            String ticket,
            String result
    ) throws ProcessException {
        if (ticket == null) {
            return null;
        } else {
            try {
                long time = System.currentTimeMillis();
                byte[] byteArray = Server.decryptToByteArrayURLSafe(ticket);
                if (byteArray.length > 8) {
                    long date = byteArray[7] & 0xFF;
                    date <<= 8;
                    date += byteArray[6] & 0xFF;
                    date <<= 8;
                    date += byteArray[5] & 0xFF;
                    date <<= 8;
                    date += byteArray[4] & 0xFF;
                    date <<= 8;
                    date += byteArray[3] & 0xFF;
                    date <<= 8;
                    date += byteArray[2] & 0xFF;
                    date <<= 8;
                    date += byteArray[1] & 0xFF;
                    date <<= 8;
                    date += byteArray[0] & 0xFF;
                    if (System.currentTimeMillis() - date > 432000000) {
                        // Ticket vencido com mais de 5 dias.
                        throw new ProcessException("TICKET EXPIRED");
                    } else {
                        String query = Core.decodeHuffman(byteArray, 8);
                        StringTokenizer tokenizer = new StringTokenizer(query, " ");
                        String command = tokenizer.nextToken();
                        if (command.equals("spam")) {
                            StringBuilder builder = new StringBuilder();
                            String recipient = null;
                            User user = null;
                            TreeSet<String> tokenSet = new TreeSet<>();
                            while (tokenizer.hasMoreTokens()) {
                                String token = tokenizer.nextToken();
                                if (isValidReputation(token)) {
                                    tokenSet.add(token);
                                    if (builder.length() > 0) {
                                        builder.append(' ');
                                    }
                                    builder.append(token);
                                } else if (token.startsWith(">") && Domain.isValidEmail(token.substring(1))) {
                                    recipient = token.substring(1);
                                } else if (token.endsWith(":") && Domain.isValidEmail(token.substring(0,token.length()-1))) {
                                    user = User.get(token.substring(0,token.length()-1));
                                }
                            }
                            TreeSet<String> blackSet = new TreeSet<>();
                            for (String key : expandTokenSet(tokenSet)) {
                                Distribution distribution = CacheDistribution.get(key, true);
                                if (Ignore.contains(key)) {
                                    distribution.addHam(date);
                                } else if (distribution.addSpam(date)) {
                                    distribution.getStatus(key);
                                    Peer.sendToAll(key, distribution);
                                }
                                blackSet.add(key);
                            }
                            if (user != null && result != null) {
                                user.setResult(date, result);
                            }
                            Server.log(time, Core.Level.DEBUG, "CMPLN", origin, ticket, blackSet, recipient);
                            return blackSet;
                        } else {
                            throw new ProcessException("TICKET INVALID");
                        }
                    }
                } else {
                    throw new ProcessException("TICKET INVALID");
                }
            } catch (ProcessException ex) {
                return addComplain(origin, ticket);
            }
        }
    }
    
    public static TreeSet<String> addComplain(
            String origin, long date,
            TreeSet<String> tokenSet,
            String recipient
    ) throws ProcessException {
        if (tokenSet == null) {
            return null;
        } else {
            long time = System.currentTimeMillis();
            TreeSet<String> blackSet = new TreeSet<>();
            for (String key : expandTokenSet(tokenSet)) {
                Distribution distribution = CacheDistribution.get(key, true);
                if (Ignore.contains(key)) {
                    distribution.addHam(date);
                } else if (distribution.addSpam(date)) {
                    distribution.getStatus(key);
                    Peer.sendToAll(key, distribution);
                }
                blackSet.add(key);
            }
            Server.log(time, Core.Level.DEBUG, "CMPLN", origin, tokenSet.toString(), blackSet, recipient);
            return blackSet;
        }
    }
    
    public static TreeSet<String> getComplain(
            String ticket) throws ProcessException {
        if (ticket == null) {
            return null;
        } else {
            TreeSet<String> tokenSet = new TreeSet<>();
            TreeSet<String> blackSet = new TreeSet<>();
            String registry = Server.decrypt(ticket);
            int index = registry.indexOf(' ');
            registry = registry.substring(index + 1);
            StringTokenizer tokenizer = new StringTokenizer(registry, " ");
            while (tokenizer.hasMoreTokens()) {
                String token = tokenizer.nextToken();
                if (isValidReputation(token)) {
                    tokenSet.add(token);
                }
            }
            for (String key : expandTokenSet(tokenSet)) {
                if (!Ignore.contains(key)) {
                    blackSet.add(key);
                }
            }
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
            String origin, String ticket
    ) throws ProcessException {
        if (ticket == null) {
            return null;
        } else {
            long time = System.currentTimeMillis();
            TreeSet<String> tokenSet = new TreeSet<>();
            String registry = Server.decrypt(ticket);
            int index = registry.indexOf(' ');
            Date date = getTicketDate(registry.substring(0, index));
            registry = registry.substring(index + 1);
            StringTokenizer tokenizer = new StringTokenizer(registry, " ");
            while (tokenizer.hasMoreTokens()) {
                String token = tokenizer.nextToken();
                if (isValidReputation(token)) {
                    tokenSet.add(token);
                }
            }
            for (String key : expandTokenSet(tokenSet)) {
                Distribution distribution = CacheDistribution.get(key, false);
                if (distribution != null && distribution.removeSpam(date.getTime())) {
                    distribution.getStatus(key);
                    Peer.sendToAll(key, distribution);
                }
            }
            Server.logQuery(time, "CLEAR", origin, tokenSet);
            return tokenSet;
        }
    }
    
    public static TreeSet<String> deleteComplainURLSafe(
            String origin, String ticket) throws ProcessException {
        if (ticket == null) {
            return null;
        } else {
            try {
                long time = System.currentTimeMillis();
                byte[] byteArray = Server.decryptToByteArrayURLSafe(ticket);
                if (byteArray.length > 8) {
                    long date = byteArray[7] & 0xFF;
                    date <<= 8;
                    date += byteArray[6] & 0xFF;
                    date <<= 8;
                    date += byteArray[5] & 0xFF;
                    date <<= 8;
                    date += byteArray[4] & 0xFF;
                    date <<= 8;
                    date += byteArray[3] & 0xFF;
                    date <<= 8;
                    date += byteArray[2] & 0xFF;
                    date <<= 8;
                    date += byteArray[1] & 0xFF;
                    date <<= 8;
                    date += byteArray[0] & 0xFF;
                    if (System.currentTimeMillis() - date > 432000000) {
                        // Ticket vencido com mais de 5 dias.
                        throw new ProcessException("TICKET EXPIRED");
                    } else {
                        String query = Core.decodeHuffman(byteArray, 8);
                        StringTokenizer tokenizer = new StringTokenizer(query, " ");
                        String command = tokenizer.nextToken();
                        if (command.equals("spam")) {
                            StringBuilder builder = new StringBuilder();
                            String recipient = null;
                            TreeSet<String> tokenSet = new TreeSet<>();
                            while (tokenizer.hasMoreTokens()) {
                                String token = tokenizer.nextToken();
                                if (isValidReputation(token)) {
                                    tokenSet.add(token);
                                    if (builder.length() > 0) {
                                        builder.append(' ');
                                    }
                                    builder.append(token);
                                } else if (token.startsWith(">") && Domain.isValidEmail(token.substring(1))) {
                                    recipient = token.substring(1);
                                }
                            }
                            for (String key : expandTokenSet(tokenSet)) {
                                Distribution distribution = CacheDistribution.get(key, false);
                                if (distribution != null && distribution.removeSpam(date)) {
                                    distribution.getStatus(key);
                                    Peer.sendToAll(key, distribution);
                                }
                            }
                            Server.logQuery(time, "CLEAR", origin, tokenSet);
                            return tokenSet;
                        } else {
                            throw new ProcessException("TICKET INVALID");
                        }
                    }
                } else {
                    throw new ProcessException("TICKET INVALID");
                }
            } catch (ProcessException ex) {
                return deleteComplain(origin, ticket);
            }
        }
    }

    /**
     * Classe que representa o cache de registros de distribuição de
     * responsáveis.
     */
    private static class CacheDistribution {

        /**
         * Mapa de distribuição binomial dos tokens encontrados.
         */
        private static final TreeMap<String,Distribution> MAP = new TreeMap<>();
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
            TreeSet<String> keySet = new TreeSet<>();
            keySet.addAll(MAP.keySet());
            return keySet;
        }
        
        private static synchronized HashMap<String,Distribution> getMap() {
            HashMap<String,Distribution> map = new HashMap<>();
            map.putAll(MAP);
            return map;
        }
        
        private static synchronized Distribution get(String key) {
            return MAP.get(key);
        }
        
        private static HashMap<String,Distribution> getCloneMap() {
            HashMap<String,Distribution> map = new HashMap<>();
            for (String key : keySet()) {
                Distribution distribution = get(key);
                if (distribution != null) {
                    map.put(key, distribution.replicate());
                }
            }
            return map;
        }
        
        private static synchronized NavigableMap<String,Distribution> getInclusiveSubMap(
                String fromKey, String toKey) {
            return MAP.subMap(fromKey, true, toKey, true);
        }
        
        private static Distribution getExact(String host) {
            return MAP.get(host);
        }
        
        private static boolean isChanged() {
            return CHANGED;
        }
        
        private static void setStored() {
            CHANGED = false;
        }
        
        private static void setLoaded() {
            CHANGED = false;
        }

        private static void store(boolean clone) {
            if (isChanged()) {
                try {
//                    Server.logTrace("storing distribution.map");
                    long time = System.currentTimeMillis();
                    File file = new File("./data/distribution.map");
                    HashMap<String,Distribution> map;
                    if (clone) {
                        map = getCloneMap();
                    } else {
                        map = getMap();
                    }
                    try (FileOutputStream outputStream = new FileOutputStream(file)) {
                        SerializationUtils.serialize(map, outputStream);
                        setStored();
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
                    try (FileInputStream fileInputStream = new FileInputStream(file)) {
                        map = SerializationUtils.deserialize(fileInputStream);
                    }
                    for (String key : map.keySet()) {
                        Object value = map.get(key);
                        if (value instanceof Distribution) {
                            Distribution distribution = (Distribution) value;
                            if (distribution.hamSet == null) {
                                distribution.hamSet = new TreeSet<>();
                            }
                            if (distribution.spamSet == null) {
                                distribution.spamSet = new TreeSet<>();
                            }
                            if (distribution.status == Status.WHITE) {
                                distribution.status = Status.GREEN;
                            }
                            if (distribution.status == Status.GRAY) {
                                distribution.status = Status.YELLOW;
                            }
                            if (distribution.status == Status.BLACK) {
                                distribution.status = Status.RED;
                            }
                            if (distribution.frequency != null) {
                                putExact(key.toLowerCase(), distribution);
                            }
                            distribution.hairCut();
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
            TreeSet<String> distributionKeySet = new TreeSet<>();
            distributionKeySet.addAll(keySet());
            for (String token : distributionKeySet) {
                Distribution distribution = getExact(token);
                if (distribution != null) {
                    if (distribution.hasLastQuery() && distribution.isExpired14()) {
                        long time = System.currentTimeMillis();
                        distribution = drop(token);
                        if (distribution != null) {
                            Server.log(time, Core.Level.DEBUG, "REPTN", token, "EXPIRED");
                        }
                    } else if (distribution.dropExpiredQuery()) {
                        distribution.getStatus(token);
                        Peer.sendToAll(token, distribution);
                    } else {
                        distribution.hairCut();
                    }
                }
            }
        }

        private static Distribution drop(String key) {
            Distribution distribution = dropExact(key);
            if (distribution != null) {
                Peer.sendToAll(key, null);
            }
            return distribution;
        }
        
        private static TreeMap<String,Distribution> getAll(String value) {
            TreeMap<String,Distribution> map = new TreeMap<>();
            NavigableMap<String,Distribution> subMap;
            Distribution distribution;
            if (Subnet.isValidIP(value)) {
                String ip = Subnet.normalizeIP(value);
                distribution = getExact(ip);
                if (distribution != null) {
                    map.put(ip, distribution);
                }
            } else if (Subnet.isValidCIDR(value)) {
                String cidr = Subnet.normalizeCIDR(value);
                String ipFirst = Subnet.getFirstIP(cidr);
                String ipLast = Subnet.getLastIP(cidr);
                if (ipFirst.compareTo(ipLast) > 0) {
                    subMap = getInclusiveSubMap(ipLast, ipFirst);
                } else {
                    subMap = getInclusiveSubMap(ipFirst, ipLast);
                }
                for (String ip : subMap.keySet()) {
                    if (Subnet.containsIP(cidr, ip)) {
                        distribution = getExact(ip);
                        if (distribution != null) {
                            map.put(ip, distribution);
                        }
                    }
                }
            } else if (Domain.isHostname(value)) {
                String host = Domain.normalizeHostname(value, true);
                do {
                    int index = host.indexOf('.') + 1;
                    host = host.substring(index);
                    if ((distribution = getExact('.' + host)) != null) {
                        map.put('.' + host, distribution);
                    } else if ((distribution = getExact('@' + host)) != null) {
                        map.put('@' + host, distribution);
                    }
                } while (host.contains("."));
            } else {
                distribution = getExact(value);
                if (distribution != null) {
                    map.put(value, distribution);
                }
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
            TreeSet<String> keySet = keySet();
            keySet.addAll(Peer.getReputationKeyAllSet());
            TreeMap<String,Distribution> distributionMap = new TreeMap<>();
            for (String key : keySet) {
                Distribution distribution = get(key, true);
                distributionMap.put(key, distribution);
            }
            return distributionMap;
        }
        
        private static TreeMap<String,Distribution> getTreeMapIPv4() {
            TreeMap<String,Distribution> distributionMap = new TreeMap<>();
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
            TreeMap<String,Distribution> distributionMap = new TreeMap<>();
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
        
        private static TreeMap<String,Binomial> getTreeMapExtendedCIDR() {
            TreeMap<String,Binomial> binomialMap = new TreeMap<>();
            for (String cidr : Block.getExtendedCIDR()) {
                Binomial binomial = new Binomial(Status.BLOCK);
                binomialMap.put(cidr, binomial);
            }
            for (String key : keySet()) {
                if (SubnetIPv4.isValidIPv4(key)) {
                    String expandedIP = null;
                    Distribution distribution = getExact(key);
                    if (distribution != null) {
                        expandedIP = SubnetIPv4.expandIPv4(key);
                        String floor = binomialMap.floorKey(expandedIP + "/9");
                        if (floor != null && floor.contains(".")) {
                            String cidr = SubnetIPv4.normalizeCIDRv4(floor);
                            if (SubnetIPv4.containsIPv4(cidr, key)) {
                                Binomial binomial = binomialMap.get(floor);
                                binomial.add(key, distribution);
                                distribution = null;
                            }
                        }
                    }
                    if (distribution != null && expandedIP != null) {
                        Binomial binomial = new Binomial(key, distribution);
                        binomialMap.put(expandedIP + "/32", binomial);
                    }
                }
            }
            return binomialMap;
        }

        private static TreeMap<String,Distribution> getMap(TreeSet<String> tokenSet) {
            TreeMap<String, Distribution> distributionMap = new TreeMap<>();
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
    
    public static Distribution getDistribution(String token) {
        return CacheDistribution.get(token, false);
    }
    
    public static Distribution getDistribution(String token, boolean create) {
        return CacheDistribution.get(token, create);
    }
    
    public static TreeMap<String,Distribution> getDistributionMapIPv4() {
        return CacheDistribution.getTreeMapIPv4();
    }
    
    public static TreeMap<String,Distribution> getDistributionMapIPv6() {
        return CacheDistribution.getTreeMapIPv6();
    }
    
    public static TreeMap<String,Binomial> getDistributionMapExtendedCIDR() {
        return CacheDistribution.getTreeMapExtendedCIDR();
    }

    public static void dropDistribution(String token) {
        CacheDistribution.drop(token);
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

    public static boolean isREGEX(String token) {
        return matches("^REGEX=[^ ]+$", token);
    }
    
    private static boolean isDNSBL(String token) {
        if (token.startsWith("DNSBL=") && token.contains(";")) {
            int index1 = token.indexOf('=');
            int index2 = token.indexOf(';');
            String server = token.substring(index1 + 1, index2);
            String value = token.substring(index2 + 1);
            return Domain.isHostname(server) && Subnet.isValidIP(value);
        } else {
            return false;
        }
    }

    private static boolean isCIDR(String token) {
        return matches("^CIDR=("
                + "((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]){1,3}\\.){1,3}"
                + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])/[0-9]{1,2})"
                + "|"
                + "((([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
                + "([0-9a-fA-F]{1,4}:){1,7}:|"
                + "([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
                + "([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
                + "([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
                + "([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
                + "([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
                + "[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
                + ":((:[0-9a-fA-F]{1,4}){1,7}|:)|"
                + "fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,})"
                + "/[0-9]{1,3})"
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
    
    public static String normalizeTokenFull(String token) throws ProcessException {
        return normalizeToken(token, true, true, true, true, true, true);
    }

    public static String normalizeToken(
            String token,
            boolean canWHOIS,
            boolean canREGEX,
            boolean canCIDR,
            boolean canDNSBL,
            boolean canHREF,
            boolean canNOTPASS
            ) throws ProcessException {
        if (token == null || token.length() == 0) {
            return null;
        } else if (canWHOIS && isWHOIS(token)) {
            return token;
        } else if (canREGEX && isREGEX(token)) {
            try {
                int index = token.indexOf('=');
                String regex = token.substring(index + 1);
                Pattern.compile(regex);
                return token;
            } catch (Exception ex) {
                return null;
            }
        } else if (canCIDR && isCIDR(token)) {
            return normalizeCIDR(token);
        } else if (canCIDR && SubnetIPv4.isValidIPv4(token)) {
            return "CIDR=" + SubnetIPv4.normalizeIPv4(token) + "/32";
        } else if (canCIDR && SubnetIPv6.isValidIPv6(token)) {
            return "CIDR=" + SubnetIPv6.normalizeIPv6(token) + "/128";
        } else if (canWHOIS && Owner.isOwnerID(token)) {
            return "WHOIS/ownerid=" + Owner.normalizeID(token);
        } else if (canCIDR && Subnet.isValidCIDR(token)) {
            return "CIDR=" + Subnet.normalizeCIDR(token);
        } else if (canDNSBL && isDNSBL(token)) {
            int index1 = token.indexOf('=');
            int index2 = token.indexOf(';');
            String server = token.substring(index1 + 1, index2);
            String value = token.substring(index2 + 1);
            server = Domain.normalizeHostname(server, false);
            value = Subnet.normalizeIP(value);
            return "DNSBL=" + server + ';' + value;
        } else if (canHREF && token.startsWith("HREF=")) {
            int index = token.indexOf('=');
            String value = token.substring(index + 1);
            if (Owner.isOwnerID(value)) {
                return "HREF=" + Owner.normalizeID(value);
            } else {
                return "HREF=" + normalizeToken(value, false, false, false, false, false, false);
            }
        } else {
            token = Core.removerAcentuacao(token);
            String recipient = "";
            if (token.contains(">")) {
                int index = token.indexOf('>');
                recipient = token.substring(index + 1);
                token = token.substring(0, index);
                if (Domain.isValidEmail(recipient)) {
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
                } else if (qualif.equals(";FAIL")) {
                    return null;
                } else if (canNOTPASS && qualif.equals(";NOTPASS")) {
                    token = token.substring(0, index);
                } else if (Domain.isHostname(qualif.substring(1))) {
                    qualif = ";" + Domain.normalizeHostname(qualif.substring(1), false);
                    token = token.substring(0, index);
                } else if (Subnet.isValidIP(qualif.substring(1))) {
                    qualif = ";" + Subnet.normalizeIP(qualif.substring(1));
                    token = token.substring(0, index);
                } else {
                    // Sintaxe com erro.
                    return null;
                }
            }
            if (Domain.isMailFrom(token)) {
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

    public static TreeSet<String> clear(String token) {
        TreeSet<String> clearSet = new TreeSet<>();
        TreeMap<String,Distribution> distribuitonMap = CacheDistribution.getAll(token);
        for (String key : distribuitonMap.keySet()) {
            Distribution distribution = distribuitonMap.get(key);
            if (distribution != null) {
                if (distribution.clear()) {
                    clearSet.add(key);
                    distribution.getStatus(token);
                    Peer.sendToAll(key, distribution);
                }
            }
            if (Block.dropExact(key)) {
                clearSet.add(key);
            }
        }
        for (String key : Block.getAllTokens(token)) {
            if (Block.dropExact(key)) {
                clearSet.add(key);
            }
        }
        return clearSet;
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
        private static final HashMap<String,String> MAP = new HashMap<>();
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
        
        private static TreeSet<String> keySet() {
            TreeSet<String> keySet = new TreeSet<>();
            keySet.addAll(MAP.keySet());
            return keySet;
        }
        
        private static HashMap<String,String> getMap() {
            HashMap<String,String> map = new HashMap<>();
            map.putAll(MAP);
            return map;
        }

        private static boolean containsExact(String address) {
            return MAP.containsKey(address);
        }
        
        private static String getExact(String host) {
            return MAP.get(host);
        }
        
        private static boolean isChanged() {
            return CHANGED;
        }
        
        private static void setStored() {
            CHANGED = false;
        }
        
        private static void setLoaded() {
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
            TreeSet<String> guessSet = new TreeSet<>();
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
            TreeSet<String> guessSet = new TreeSet<>();
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
                    try (FileOutputStream outputStream = new FileOutputStream(file)) {
                        SerializationUtils.serialize(map, outputStream);
                        setStored();
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
                    try (FileInputStream fileInputStream = new FileInputStream(file)) {
                        map = SerializationUtils.deserialize(fileInputStream);
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

    public static void storeGuess() {
        CacheGuess.store();
    }

    public static void storeSPF() {
        CacheSPF.store();
    }

    /**
     * Armazenamento de cache em disco.
     */
    public static void store(boolean clone) {
        CacheSPF.store();
        CacheDistribution.store(clone);
        CacheGuess.store();
        CacheHELO.store();
    }

    /**
     * Carregamento de cache do disco.
     */
    public static void load() {
        CacheSPF.load();
        CacheDistribution.load();
        CacheGuess.load();
        CacheHELO.load();
    }
    
    public static String getUniqueIP(String helo) {
        String IPv4 = CacheHELO.getUniqueIPv4(helo);
        String IPv6 = CacheHELO.getUniqueIPv6(helo);
        if (IPv4 == null) {
            return IPv6;
        } else if (IPv6 == null) {
            return IPv4;
        } else {
            return null;
        }
    }
    
    public static String getUniqueIPv4(String helo) {
        return CacheHELO.getUniqueIPv4(helo);
    }
    
    public static String getUniqueIPv6(String helo) {
        return CacheHELO.getUniqueIPv6(helo);
    }

    /**
     * Classe que representa o cache de resolução de HELO.
     */
    private static class CacheHELO {

        /**
         * Mapa de atributos da verificação de HELO.
         */
        private static final HashMap<String,HELO> MAP = new HashMap<>();
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
            TreeSet<String> keySet = new TreeSet<>();
            keySet.addAll(MAP.keySet());
            return keySet;
        }
        
        private static synchronized HashMap<String,HELO> getMap() {
            HashMap<String,HELO> map = new HashMap<>();
            map.putAll(MAP);
            return map;
        }
        
        private static HELO getExact(String host) {
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
                    TreeSet<String> ipv4Set = new TreeSet<>();
                    try {
                        Attributes attributesA = Server.getAttributesDNS(
                                hostname, new String[]{"A"}
                        );
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
                        }
                    } catch (CommunicationException ex) {
                        Server.logLookupHELO(time, "A " + hostname, "TIMEOUT");
                    } catch (ServiceUnavailableException ex) {
                        Server.logLookupHELO(time, "A " + hostname, "SERVFAIL");
                    }
                    TreeSet<String> ipv6Set = new TreeSet<>();
                    try {
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
                    } catch (CommunicationException ex) {
                        Server.logLookupHELO(time, "AAAA " + hostname, "TIMEOUT");
                    } catch (ServiceUnavailableException ex) {
                        Server.logLookupHELO(time, "AAAA " + hostname, "SERVFAIL");
                    }
                    this.addressSet = new TreeSet<>();
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
                } catch (NameNotFoundException ex) {
                    this.addressSet = null;
                    this.address4 = null;
                    this.address6 = null;
                    Server.logLookupHELO(time, hostname, "NXDOMAIN");
                } catch (NamingException ex) {
                    this.addressSet = null;
                    this.address4 = null;
                    this.address6 = null;
                    Server.logLookupHELO(time, hostname, "ERROR " + ex.getClass() + " " + ex.getExplanation());
                } finally {
                    this.queryCount = 0;
                    CHANGED = true;
                }
            }
            
            public TreeSet<String> getAddressSet() {
                TreeSet<String> set = new TreeSet<>();
                set.addAll(this.addressSet);
                return set;
            }
            
            public boolean contains(String ip) {
                if ((ip = Subnet.normalizeIP(ip)) == null) {
                    return false;
                } else if (addressSet == null) {
                    return false;
                } else {
                    return addressSet.contains(ip);
                }
            }
            
            public String getAddress4() {
                return address4;
            }
            
            public String getAddress6() {
                return address6;
            }

            public boolean isExpired7() {
                return System.currentTimeMillis() - lastQuery > 604800000;
            }
            
            public boolean isExpired14() {
                return System.currentTimeMillis() - lastQuery > 1209600000;
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

        public static boolean match(String ip, String helo, boolean refresh) {
            if (ip == null) {
                return false;
            } else if ((helo = Domain.extractHost(helo, false)) == null) {
                return false;
            } else {
                HELO heloObj = getExact(helo);
                if (heloObj == null) {
                    heloObj = new HELO(helo);
                    putExact(helo, heloObj);
                } else if (refresh) {
                    heloObj.refresh(helo);
                    addQuery(helo, heloObj);
                    CHANGED = true;
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
                    try (FileOutputStream outputStream = new FileOutputStream(file)) {
                        SerializationUtils.serialize(map, outputStream);
                        CHANGED = false;
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
                    try (FileInputStream fileInputStream = new FileInputStream(file)) {
                        map = SerializationUtils.deserialize(fileInputStream);
                    }
                    for (String key : map.keySet()) {
                        Object value = map.get(key);
                        if (value instanceof HELO) {
                            HELO helo = (HELO) value;
//                            helo.update();
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
    
    public static boolean matchHELO(String ip, String helo, boolean refresh) {
        return CacheHELO.match(ip, helo, refresh);
    }
    
    public static boolean matchHELO(String ip, String helo) {
        return CacheHELO.match(ip, helo, false);
    }

    protected static String processPostfixSPF(
            InetAddress ipAddress,
            Client client,
            User user,
            String ip,
            String sender,
            String helo,
            String recipient,
            LinkedList<User> userResult
            ) throws ProcessException {
        if (sender == null) {
            sender = null;
        } else if (sender.trim().length() == 0) {
            sender = null;
        } else if (Domain.isMailFrom(sender)) {
            sender = sender.toLowerCase();
        } else {
            return "action=554 5.7.1 SPFBL " + sender + " "
                    + "is not a valid e-mail address. "
                    + "See http://spfbl.net/en/feedback\n\n";
        }
        if (recipient == null) {
            recipient = null;
        } else if (recipient.trim().length() == 0) {
            recipient = null;
        } else if (Domain.isValidEmail(recipient)) {
            recipient = recipient.toLowerCase();
        } else {
            return "action=554 5.7.1 SPFBL " + recipient + " "
                    + "is not a valid e-mail address. "
                    + "See http://spfbl.net/en/feedback\n\n";
        }
        if (!Domain.isHostname(helo)) {
            helo = null;
        }
        ip = SubnetIPv6.tryTransformToIPv4(ip);
        if (!Subnet.isValidIP(ip)) {
            return "action=554 5.7.1 SPFBL "
                    + ip + " is not a valid public IP. "
                    + "See http://spfbl.net/en/feedback\n\n";
        } else if (sender != null && !Domain.isMailFrom(sender)) {
            return "action=554 5.7.1 SPFBL "
                    + sender + " is not a valid sender. "
                    + "See http://spfbl.net/en/feedback\n\n";
        } else if (recipient != null && !Domain.isValidEmail(recipient)) {
            return "action=554 5.7.1 SPFBL "
                    + recipient + " is not a valid recipient. "
                    + "See http://spfbl.net/en/feedback\n\n";
        } else if (Subnet.isReservedIP(ip)) {
            // Message from LAN.
            return "action=DUNNO\n\n";
        } else if (client != null && client.containsFull(ip)) {
            // Message from LAN.
            return "action=DUNNO\n\n";
        } else {
            try {
                TreeSet<String> tokenSet = new TreeSet<>();
                ip = Subnet.normalizeIP(ip);
                tokenSet.add(Subnet.normalizeIP(ip));
                if (Domain.isValidEmail(recipient)) {
                    // Se houver um remetente válido,
                    // Adicionar no ticket para controle externo.
                    tokenSet.add('>' + recipient);
                }
                if (recipient != null) {
                    User recipientUser = User.get(recipient);
                    if (recipientUser == null) {
                        // Se a consulta originar de destinatário com postmaster cadastrado,
                        // considerar o próprio postmaster como usuário da consulta.
                        int index = recipient.indexOf('@');
                        String postmaster = "postmaster" + recipient.substring(index);
                        User postmasterUser = User.get(postmaster);
                        if (postmasterUser != null) {
                            user = postmasterUser;
                        }
                    } else {
                        user = recipientUser;
                    }
                }
                if (user != null) {
                    userResult.add(user);
                    tokenSet.add(user.getEmail() + ':');
                } else if (client != null && client.hasEmail()) {
                    tokenSet.add(client.getEmail() + ':');
                }
                // Passar a acompanhar todos os 
                // HELO quando apontados para o IP para 
                // uma nova forma de interpretar dados.
                String hostname;
                if (CacheHELO.match(ip, helo, false)) {
                    hostname = Domain.normalizeHostname(helo, true);
                } else {
                    hostname = Reverse.getHostname(ip);
                    hostname = Domain.normalizeHostname(hostname, true);
                }
                if (White.isDesactive(client, user, ip, hostname, recipient)) {
                    // SPFBL desactived for this case.
                    return "action=DUNNO\n\n";
                } else if (hostname == null) {
                    Server.logDebug("no rDNS for " + ip + ".");
                } else if (Domain.isOfficialTLD(hostname)) {
                    return "action=554 5.7.1 SPFBL "
                            + hostname + " is a reserved domain. "
                            + "See http://spfbl.net/en/feedback\n\n";
                } else {
                    // Verificação de pilha dupla,
                    // para pontuação em ambas pilhas.
                    String ipv4 = CacheHELO.getUniqueIPv4(hostname);
                    String ipv6 = CacheHELO.getUniqueIPv6(hostname);
                    if (ip.equals(ipv6) && CacheHELO.match(ipv4, hostname, false)) {
                        // Equivalência de pilha dupla se 
                        // IPv4 for único para o hostname.
                        tokenSet.add(ipv4);
                    } else if (ip.equals(ipv4) && CacheHELO.match(ipv6, hostname, false)) {
                        // Equivalência de pilha dupla se 
                        // IPv6 for único para o hostname.
                        tokenSet.add(ipv6);
                    }
                }
                if (Generic.containsGenericSoft(hostname)) {
                    // Quando o reverso for 
                    // genérico, não considerá-lo.
                    hostname = null;
                } else if (hostname != null) {
                    tokenSet.add(hostname);
                }
                String result;
                LinkedList<String> logList = new LinkedList<>();
                SPF spf;
                if (sender == null) {
                    spf = null;
                    result = "NONE";
                } else if (Domain.isOfficialTLD(sender)) {
                    spf = null;
                    result = "NONE";
                } else if (Generic.containsGeneric(sender)) {
                    spf = null;
                    result = "NONE";
                } else if ((spf = CacheSPF.get(sender)) == null) {
                    result = "NONE";
                } else if (spf.isInexistent()) {
                    result = "NONE";
                } else {
                    result = spf.getResult(ip, sender, helo, logList);
                }
                String origem;
                String fluxo;
                String mx = Domain.extractHost(sender, true);
//                if (user != null && user.isLocal()) {
//                    // Message from local user.
//                    return "action=DUNNO\n\n";
//                } else
                if (recipient != null && result.equals("PASS")) {
                    if (recipient.endsWith(mx)) {
                        // Message from same domain.
                        return "action=DUNNO\n\n";
                    } else if (
                            recipient.equals(Core.getAbuseEmail()) &&
                            User.exists(sender, "postmaster" + mx)
                            ) {
                        // Message to abuse.
                        return "action=DUNNO\n\n";
                    }
                }
                if (result.equals("PASS") || (sender != null && Provider.containsHELO(ip, helo))) {
                    // Quando fo PASS, significa que o domínio
                    // autorizou envio pelo IP, portanto o dono dele
                    // é responsavel pelas mensagens.
                    if (!Provider.containsExact(mx)) {
                        // Não é um provedor então
                        // o MX deve ser listado.
                        tokenSet.add(mx);
                        origem = mx;
                    } else if (Domain.isValidEmail(sender)) {
                        // Listar apenas o remetente se o
                        // hostname for um provedor de e-mail.
                        String userEmail = null;
                        String recipientEmail = null;
                        for (String token : tokenSet) {
                            if (token.endsWith(":")) {
                                userEmail = token;
                            } else if (token.startsWith(">")) {
                                recipientEmail = token;
                            }
                        }
                        tokenSet.clear();
                        tokenSet.add(sender);
                        if (userEmail != null) {
                            tokenSet.add(userEmail);
                        }
                        if (recipientEmail != null) {
                            tokenSet.add(recipientEmail);
                        }
                        origem = sender;
                    } else {
                        origem = sender;
                    }
                    fluxo = origem + ">" + recipient;
                } else if (hostname == null) {
                    origem = (sender == null ? "" : sender + '>') + ip;
                    fluxo = origem + ">" + recipient;
                } else {
                    String dominio = Domain.extractDomain(hostname, true);
                    origem = (sender == null ? "" : sender + '>') + (dominio == null ? hostname : dominio.substring(1));
                    fluxo = origem + ">" + recipient;
                }
                Long recipientTrapTime = Trap.getTimeRecipient(client, user, recipient);
                if (recipientTrapTime == null && White.contains(client, user, ip, sender, hostname, result, recipient)) {
//                    if (user != null) {
                        if (White.contains(client, user, ip, sender, hostname, result, null)) {
                            // Limpa da lista BLOCK um possível falso positivo.
                            Block.clear(client, user, ip, sender, hostname, result, null);
                        }
//                    }
                    // Calcula frequencia de consultas.
                    String url = Core.getURL(user);
                    String ticket = SPF.addQueryHam(
                            client, user, ip, helo, hostname, sender,
                            result, recipient, tokenSet, "WHITE"
                    );
                    return "action=PREPEND "
                            + "Received-SPFBL: " + result + " "
                            + (url == null ? ticket : url + ticket) + "\n\n";
                } else if (Block.contains(client, user, ip, sender, hostname, result, recipient, true, true, true, true)) {
                    if (recipientTrapTime == null) {
                        Action action = client == null ? Action.REJECT : client.getActionBLOCK();
                        if (action == Action.REJECT) {
                            // Calcula frequencia de consultas.
                            Object[] resultSet = SPF.addQuerySpam(
                                    client, user, ip, helo, hostname, sender,
                                    result, recipient, tokenSet, "BLOCK"
                            );
                            User.Query queryLocal = (User.Query) (resultSet == null ? null : resultSet[1]);
                            if (queryLocal != null && queryLocal.needHeader()) {
                                action = client == null ? Action.FLAG : client.getActionRED();
                                if (action == Action.HOLD) {
                                    queryLocal.setResult("HOLD");
                                    return "action=HOLD blocked.\n\n";
                                } else {
                                    queryLocal.setResult("FLAG");
                                    return "action=PREPEND X-Spam-Flag: YES\n\n";
                                }
                            } else {
                                String url = Core.getUnblockURL(
                                        client, user, ip,
                                        sender, hostname, recipient
                                );
                                if (url == null) {
                                    return "action=554 5.7.1 SPFBL "
                                        + "you are permanently blocked. "
                                            + "See http://spfbl.net/en/feedback\n\n";
                                } else {
                                    return "action=554 5.7.1 SPFBL "
                                        + "BLOCKED " + url + "\n\n";
                                }
                            }
                        } else if (action == Action.FLAG) {
                            SPF.addQuery(
                                    client, user, ip, helo, hostname, sender,
                                    result, recipient, tokenSet, "FLAG"
                            );
                            return "action=PREPEND X-Spam-Flag: YES\n\n";
                        } else if (action == Action.HOLD) {
                            SPF.addQuery(
                                    client, user, ip, helo, hostname, sender,
                                    result, recipient, tokenSet, "HOLD"
                            );
                            return "action=HOLD blocked.\n\n";
                        } else {
                            return "action=WARN undefined action.\n\n";
                        }
                    } else {
                        Object[] resultSet = SPF.addQuerySpam(
                                client, user, ip, helo, hostname, sender,
                                result, recipient, tokenSet, "BLOCK"
                        );
                        long time = resultSet == null ? Server.getNewUniqueTime() : (Long) resultSet[0];
                        User.Query queryLocal = resultSet == null ? null : (User.Query) resultSet[1];
                        if (queryLocal != null && queryLocal.blockKey(time)) {
                            Server.logDebug("new BLOCK '" + queryLocal.getUserEmail() + ":" + queryLocal.getBlockKey() + "' added by '" + recipient + ";INEXISTENT'.");
                        }
                        String url = Core.getUnblockURL(
                                client, user, ip,
                                sender, hostname, recipient
                        );
                        if (url == null) {
                            return "action=554 5.7.1 SPFBL "
                                + "you are permanently blocked. "
                                    + "See http://spfbl.net/en/feedback\n\n";
                        } else {
                            return "action=554 5.7.1 SPFBL "
                                + "BLOCKED " + url + "\n\n";
                        }
                    }
                } else if (Generic.containsDynamicDomain(hostname)) {
                    if (Analise.isRunning()) {
                        // Bloquear automaticamente range de IP dinâmico.
                        String cidr = Subnet.normalizeCIDR(SubnetIPv4.isValidIPv4(ip) ? ip + "/24" : ip + "/48");
                        if (Block.tryOverlap(cidr)) {
                            Server.logDebug("new BLOCK '" + cidr + "' added by '" + hostname + ";DYNAMIC'.");
                        } else if (Block.tryAdd(ip)) {
                            Server.logDebug("new BLOCK '" + ip + "' added by '" + hostname + ";DYNAMIC'.");
                        }
                    }
                    SPF.addQuerySpam(
                            client, user, ip, helo, hostname, sender,
                            result, recipient, tokenSet, "INVALID"
                    );
                    return "action=554 5.7.1 SPFBL dynamic IP. "
                            + "See http://spfbl.net/en/feedback\n\n";
                } else if (spf != null && spf.isDefinitelyInexistent()) {
                    // Bloquear automaticamente IP com reputação vermelha.
                    if (Analise.isRunning() && SPF.isRed(ip)) {
                        if (Block.tryAdd(ip)) {
                            Server.logDebug("new BLOCK '" + ip + "' added by '" + mx + ";NXDOMAIN'.");
                        }
                    }
                    Analise.processToday(ip);
                    // O domínio foi dado como inexistente inúmeras vezes.
                    // Rejeitar e denunciar o host pois há abuso de tentativas.
                    SPF.addQuerySpam(
                            client, user, ip, helo, hostname, sender,
                            result, recipient, tokenSet, "NXDOMAIN"
                    );
                    return "action=554 5.7.1 SPFBL "
                            + "sender has non-existent internet domain. "
                            + "See http://spfbl.net/en/feedback\n\n";
                } else if (spf != null && spf.isInexistent()) {
                    Analise.processToday(ip);
                    SPF.addQuery(
                            client, user, ip, helo, hostname, sender,
                            result, recipient, tokenSet, "GREYLIST"
                    );
                    return "action=451 4.7.1 SPFBL you are greylisted. "
                            + "See http://spfbl.net/en/feedback\n\n";
                } else if (result.equals("FAIL")) {
                    // Bloquear automaticamente IP com reputação vermelha.
                    if (Analise.isRunning() && SPF.isRed(ip)) {
                        if (Block.tryAdd(ip)) {
                            Server.logDebug("new BLOCK '" + ip + "' added by '" + sender + ";FAIL'.");
                        }
                    }
                    Analise.processToday(ip);
                    SPF.addQuerySpam(
                            client, user, ip, helo, hostname, sender,
                            result, recipient, tokenSet, "FAIL"
                    );
                    // Retornar REJECT somente se não houver 
                    // liberação literal do remetente com FAIL.
                    return "action=554 5.7.1 SPFBL "
                            + sender + " is not allowed to "
                            + "send mail from " + ip + ". "
                            + "See http://spfbl.net/en/feedback\n\n";
                } else if (sender != null && !Domain.isMailFrom(sender)) {
                    // Bloquear automaticamente IP com reputação vermelha.
                    if (Analise.isRunning() && SPF.isRed(ip)) {
                        if (Block.tryAdd(ip)) {
                            Server.logDebug("new BLOCK '" + ip + "' added by '" + sender + ";INVALID'.");
                        }
                    }
                    Analise.processToday(ip);
                    SPF.addQuerySpam(
                            client, user, ip, helo, hostname, sender,
                            result, recipient, tokenSet, "INVALID"
                    );
                    return "action=554 5.7.1 SPFBL "
                            + sender + " is not a valid e-mail address. "
                            + "See http://spfbl.net/en/feedback\n\n";
                } else if (sender != null && Domain.isOfficialTLD(sender)) {
                    // Bloquear automaticamente IP com reputação vermelha.
                    if (Analise.isRunning() && SPF.isRed(ip)) {
                        if (Block.tryAdd(ip)) {
                            Server.logDebug("new BLOCK '" + ip + "' added by '" + sender + ";RESERVED'.");
                        }
                    }
                    Analise.processToday(ip);
                    SPF.addQuerySpam(
                            client, user, ip, helo, hostname, sender,
                            result, recipient, tokenSet, "RESERVED"
                    );
                    return "action=554 5.7.1 SPFBL "
                            + sender + " has a reserved domain. "
                            + "See http://spfbl.net/en/feedback\n\n";
                } else if (sender == null && !CacheHELO.match(ip, hostname, false)) {
                    // Bloquear automaticamente IP com reputação ruim.
                    if (Analise.isRunning() && SPF.isRed(ip)) {
                        if (Block.tryAdd(ip)) {
                            Server.logDebug("new BLOCK '" + ip + "' added by '" + hostname + ";INVALID'.");
                        }
                    }
                    Analise.processToday(ip);
                    SPF.addQuerySpam(
                            client, user, ip, helo, hostname, sender,
                            result, recipient, tokenSet, "INVALID"
                    );
                    return "action=554 5.7.1 SPFBL invalid hostname. "
                            + "See http://spfbl.net/en/feedback\n\n";
                } else if (hostname == null && Core.isReverseRequired()) {
                    if (Analise.isRunning() && Block.tryAdd(ip)) {
                        Server.logDebug("new BLOCK '" + ip + "' added by 'NONE'.");
                    }
                    Analise.processToday(ip);
                    SPF.addQuerySpam(
                            client, user, ip, helo, hostname, sender,
                            result, recipient, tokenSet, "INVALID"
                    );
                    return "action=554 5.7.1 SPFBL " + ip + " has no rDNS. "
                            + "See http://spfbl.net/en/feedback\n\n";
                } else if (recipient != null && !Domain.isValidEmail(recipient)) {
                    Analise.processToday(ip);
                    Analise.processToday(mx);
                    SPF.getTicket(
                            client, user, ip, helo, hostname, sender,
                            result, recipient, tokenSet, "INEXISTENT"
                    );
                    return "action=550 5.1.1 SPFBL the account "
                            + "that you tried to reach does not exist. "
                            + "See http://spfbl.net/en/feedback\n\n";
                } else if (recipientTrapTime != null) {
                    if (System.currentTimeMillis() > recipientTrapTime) {
                        // Spamtrap.
                        for (String token : tokenSet) {
                            String block;
                            Status status = SPF.getStatus(token);
                            if (status == Status.RED && Analise.isRunning() && (block = Block.addSafe(token)) != null) {
                                Server.logDebug("new BLOCK '" + block + "' added by '" + recipient + ";SPAMTRAP'.");
                                Peer.sendBlockToAll(block);
                            }
                            if (status != Status.GREEN && !Subnet.isValidIP(token) && (block = Block.addIfNotNull(user, token)) != null) {
                                Server.logDebug("new BLOCK '" + block + "' added by '" + recipient + ";SPAMTRAP'.");
                            }
                        }
                        Analise.processToday(ip);
                        Analise.processToday(mx);
                        // Calcula frequencia de consultas.
                        SPF.addQuerySpam(
                                client, user, ip, helo, hostname, sender,
                                result, recipient, tokenSet, "TRAP"
                        );
                        return "action=DISCARD SPFBL discarded by spamtrap.\n\n";
                    } else {
                        // Inexistent.
                        for (String token : tokenSet) {
                            String block;
                            Status status = SPF.getStatus(token);
                            if (status == Status.RED && Analise.isRunning() && (block = Block.addSafe(token)) != null) {
                                Server.logDebug("new BLOCK '" + block + "' added by '" + recipient + ";INEXISTENT'.");
                                Peer.sendBlockToAll(block);
                            }
                            if (status != Status.GREEN && !Subnet.isValidIP(token) && (block = Block.addIfNotNull(user, token)) != null) {
                                Server.logDebug("new BLOCK '" + block + "' added by '" + recipient + ";INEXISTENT'.");
                            }
                        }
                        Analise.processToday(ip);
                        Analise.processToday(mx);
                        SPF.getTicket(
                                client, user, ip, helo, hostname, sender,
                                result, recipient, tokenSet, "INEXISTENT"
                        );
                        return "action=550 5.1.1 SPFBL the account "
                                + "that you tried to reach does not exist. "
                                + "See http://spfbl.net/en/feedback\n\n";
                    }
                } else if (result.equals("PASS") && SPF.isGood(Provider.containsExact(mx) ? sender : mx)) {
                    // O remetente é válido e tem excelente reputação,
                    // ainda que o provedor dele esteja com reputação ruim.
                    String url = Core.getURL(user);
                    String ticket = SPF.addQueryHam(
                            client, user, ip, helo, hostname, sender,
                            result, recipient, tokenSet, "ACCEPT"
                    );
                    return "action=PREPEND "
                            + "Received-SPFBL: PASS "
                            + (url == null ? ticket : url + URLEncoder.encode(ticket, "UTF-8")) + "\n\n";
                } else if (Defer.count(fluxo) > Core.getFloodMaxRetry()) {
                    Analise.processToday(ip);
                    Analise.processToday(mx);
                    // A origem atingiu o limite de atraso 
                    // para liberação do destinatário.
                    long time = System.currentTimeMillis();
                    Defer.end(fluxo);
                    Server.logDefer(time, fluxo, "DEFER FLOOD");
                    SPF.addQuerySpam(
                            client, user, ip, helo, hostname, sender,
                            result, recipient, tokenSet, "REJECT"
                    );
                    return "action=554 5.7.1 SPFBL too many retries. "
                            + "See http://spfbl.net/en/feedback\n\n";
                } else if (!result.equals("PASS") && !CacheHELO.match(ip, hostname, false)) {
                    // Bloquear automaticamente IP com reputação amarela.
                    if (Analise.isRunning() && SPF.isRed(ip)) {
                        if (Block.tryAdd(ip)) {
                            Server.logDebug("new BLOCK '" + ip + "' added by '" + recipient + ";INVALID'.");
                        }
                    }
                    Analise.processToday(ip);
                    SPF.addQuerySpam(
                            client, user, ip, helo, hostname, sender,
                            result, recipient, tokenSet, "INVALID"
                    );
                    return "action=554 5.7.1 SPFBL invalid hostname. "
                            + "See http://spfbl.net/en/feedback\n\n";
                } else if (recipient != null && recipient.startsWith("postmaster@")) {
                    String url = Core.getURL(user);
                    String ticket = SPF.getTicket(
                            client, user, ip, helo, hostname, sender,
                            result, recipient, tokenSet, "ACCEPT"
                    );
                    return "action=PREPEND "
                            + "Received-SPFBL: " + result + " "
                            + (url == null ? ticket : url + URLEncoder.encode(ticket, "UTF-8")) + "\n\n";
                } else if (SPF.hasRed(tokenSet)) {
                    Analise.processToday(ip);
                    Analise.processToday(mx);
                    Action action = client == null ? Action.FLAG : client.getActionRED();
                    if (action == Action.REJECT) {
                        // Calcula frequencia de consultas.
                        SPF.addQuerySpam(
                                client, user, ip, helo, hostname, sender,
                                result, recipient, tokenSet, "REJECT"
                        );
                        return "action=554 5.7.1 SPFBL "
                                + "you are temporarily listed. "
                                + "See http://spfbl.net/en/feedback\n\n";
                    } else if (action == Action.DEFER) {
                        if (Defer.defer(fluxo, Core.getDeferTimeRED())) {
                            // Pelo menos um identificador está listado e com atrazo programado de um dia.
                            String url = Core.getReleaseURL(user, fluxo);
                            SPF.addQuery(
                                    client, user, ip, helo, hostname, sender,
                                    result, recipient, tokenSet, "LISTED"
                            );
                            if (url == null || Defer.count(fluxo) > 1) {
                                return "action=451 4.7.2 SPFBL "
                                        + "you are temporarily listed. "
                                        + "See http://spfbl.net/en/feedback\n\n";
                            } else if (result.equals("PASS") && enviarLiberacao(url, sender, recipient)) {
                                // Envio da liberação por e-mail se 
                                // houver validação do remetente por PASS.
                                return "action=451 4.7.2 SPFBL "
                                        + "you are temporarily listed. "
                                        + "See http://spfbl.net/en/feedback\n\n";
                            } else {
                                return "action=451 4.7.2 SPFBL LISTED " + url + "\n\n";
                            }
                        } else {
                            // Calcula frequencia de consultas.
                            SPF.addQuerySpam(
                                    client, user, ip, helo, hostname, sender,
                                    result, recipient, tokenSet, "REJECT"
                            );
                            return "action=554 5.7.1 SPFBL too many retries. "
                                    + "See http://spfbl.net/en/feedback\n\n";
                        }
                    } else if (action == Action.FLAG) {
                        SPF.addQuery(
                                client, user, ip, helo, hostname, sender,
                                result, recipient, tokenSet, "FLAG"
                        );
                        return "action=PREPEND X-Spam-Flag: YES\n\n";
                    } else if (action == Action.HOLD) {
                        SPF.addQuery(
                                client, user, ip, helo, hostname, sender,
                                result, recipient, tokenSet, "HOLD"
                        );
                        return "action=HOLD very bad reputation.\n\n";
                    } else {
                        SPF.addQuery(
                                client, user, ip, helo, hostname, sender,
                                result, recipient, tokenSet, "FLAG"
                        );
                        return "action=WARN undefined action.\n\n";
                    }
                } else if (Domain.isGraceTime(sender) || Domain.isGraceTime(hostname)) {
                    Server.logTrace("domain in grace time.");
                    for (String token : tokenSet) {
                        String block;
                        Status status = SPF.getStatus(token);
                        if (status == Status.RED && Analise.isRunning() && (block = Block.addSafe(token)) != null) {
                            Server.logDebug("new BLOCK '" + block + "' added by '" + status + "'.");
                            Peer.sendBlockToAll(block);
                        }
                        if (status != Status.GREEN && !Subnet.isValidIP(token) && (block = Block.addIfNotNull(user, token)) != null) {
                            Server.logDebug("new BLOCK '" + block + "' added by '" + status + "'.");
                        }
                    }
                    Analise.processToday(ip);
                    Analise.processToday(mx);
                    Action action = client == null ? Action.REJECT : client.getActionGRACE();
                    if (action == Action.REJECT) {
                        // Calcula frequencia de consultas.
                        SPF.addQuerySpam(
                                client, user, ip, helo, hostname, sender,
                                result, recipient, tokenSet, "REJECT"
                        );
                        return "action=554 5.7.1 SPFBL "
                                + "your domain is in grace time. "
                                + "See http://spfbl.net/en/feedback\n\n";
                    } else if (action == Action.DEFER) {
                        if (Defer.defer(fluxo, Core.getDeferTimeYELLOW())) {
                            SPF.addQuery(
                                    client, user, ip, helo, hostname, sender,
                                    result, recipient, tokenSet, "GREYLIST"
                            );
                            return "action=451 4.7.1 SPFBL you are greylisted. "
                                    + "See http://spfbl.net/en/feedback\n\n";
                        } else {
                            SPF.addQuery(
                                    client, user, ip, helo, hostname, sender,
                                    result, recipient, tokenSet, "FLAG"
                            );
                            return "action=PREPEND X-Spam-Flag: YES\n\n";
                        }
                    } else if (action == Action.HOLD) {
                        SPF.addQuery(
                                client, user, ip, helo, hostname, sender,
                                result, recipient, tokenSet, "HOLD"
                        );
                        return "action=HOLD domain in grace time.\n\n";
                    } else {
                        SPF.addQuery(
                                client, user, ip, helo, hostname, sender,
                                result, recipient, tokenSet, "FLAG"
                        );
                        return "action=PREPEND X-Spam-Flag: YES\n\n";
                    }
                } else if (Provider.containsHELO(ip, hostname)) {
                    // Calcula frequencia de consultas.
                    String url = Core.getURL(user);
                    String ticket = SPF.addQueryHam(
                            client, user, ip, helo, hostname, sender,
                            result, recipient, tokenSet, "ACCEPT"
                    );
                    return "action=PREPEND "
                            + "Received-SPFBL: " + result + " "
                            + (url == null ? ticket : url + URLEncoder.encode(ticket, "UTF-8")) + "\n\n";
                } else if (SPF.hasYellow(tokenSet)) {
                    Analise.processToday(ip);
                    Analise.processToday(mx);
                    boolean defer = Defer.defer(fluxo, Core.getDeferTimeYELLOW());
                    Action action = client == null ? Action.DEFER : client.getActionYELLOW();
                    if (defer && action == Action.DEFER) {
                        // Pelo menos um identificador está em greylisting com atrazo programado de 10min.
                        SPF.addQuery(
                                client, user, ip, helo, hostname, sender,
                                result, recipient, tokenSet, "GREYLIST"
                        );
                        return "action=451 4.7.1 SPFBL you are greylisted. "
                                + "See http://spfbl.net/en/feedback\n\n";
                    } else if (defer && action == Action.HOLD) {
                        SPF.addQuery(
                                client, user, ip, helo, hostname, sender,
                                result, recipient, tokenSet, "HOLD"
                        );
                        return "action=HOLD bad reputation.\n\n";
                    } else {
                        SPF.addQuery(
                                client, user, ip, helo, hostname, sender,
                                result, recipient, tokenSet, "FLAG"
                        );
                        return "action=PREPEND X-Spam-Flag: YES\n\n";
                    }
                } else if (SPF.isFlood(tokenSet) && Defer.defer(origem, Core.getDeferTimeFLOOD())) {
                    Analise.processToday(ip);
                    Analise.processToday(mx);
                    // Pelo menos um identificador está com frequência superior ao permitido.
                    Server.logDebug("FLOOD " + tokenSet);
                    SPF.addQuery(
                            client, user, ip, helo, hostname, sender,
                            result, recipient, tokenSet, "GREYLIST"
                    );
                    return "action=451 4.7.1 SPFBL you are greylisted. "
                            + "See http://spfbl.net/en/feedback\n\n";
                } else if (result.equals("SOFTFAIL") && Defer.defer(fluxo, Core.getDeferTimeSOFTFAIL())) {
                    Analise.processToday(ip);
                    Analise.processToday(mx);
                    // SOFTFAIL com atrazo programado de 1min.
                    SPF.addQuery(
                            client, user, ip, helo, hostname, sender,
                            result, recipient, tokenSet, "GREYLIST"
                    );
                    return "action=451 4.7.1 SPFBL you are greylisted. See http://spfbl.net/en/feedback\n\n";
                } else {
                    Analise.processToday(ip);
                    Analise.processToday(mx);
                    // Calcula frequencia de consultas.
                    String url = Core.getURL(user);
                    String ticket = SPF.addQueryHam(
                            client, user, ip, helo, hostname, sender,
                            result, recipient, tokenSet, "ACCEPT"
                    );
                    return "action=PREPEND "
                            + "Received-SPFBL: " + result + " "
                            + (url == null ? ticket : url + URLEncoder.encode(ticket, "UTF-8")) + "\n\n";
                }
            } catch (ProcessException ex) {
                if (ex.isErrorMessage("SPF PARSE")) {
                    return "action=REJECT [SPF] "
                            + "One or more SPF records from " + sender + " "
                            + "could not be interpreted. "
                            + "Please see http://www.openspf.org/SPF_"
                            + "Record_Syntax for details.\n\n";
                } else if (ex.isErrorMessage("RESERVED")) {
                    return "action=REJECT [SPF] "
                            + "The domain of "
                            + sender + " is a reserved TLD.\n\n";
                } else if (sender == null) {
                    Server.logError(ex);
                    return "action=DEFER [SPF] "
                            + "A transient error occurred. "
                            + "Try again later.\n\n";
                } else {
                    return "action=DEFER [SPF] "
                            + "A transient error occurred when "
                            + "checking SPF record from " + sender + ", "
                            + "preventing a result from being reached. "
                            + "Try again later.\n\n";
                }
            } catch (Exception ex) {
                Server.logError(ex);
                return "action=WARN SPFBL fatal error.\n\n";
            }
        }
    }
    
    public static String getRecipient(String ticket) throws ProcessException {
        if (ticket == null) {
            return null;
        } else {
            String registry = Server.decrypt(ticket);
            int index = registry.indexOf(' ');
            Date date = getTicketDate(registry.substring(0, index));
            if (System.currentTimeMillis() - date.getTime() > 432000000) {
                // Ticket vencido com mais de 5 dias.
                throw new ProcessException("TICKET EXPIRED");
            } else {
                registry = registry.substring(index + 1);
                StringTokenizer tokenizer = new StringTokenizer(registry, " ");
                while (tokenizer.hasMoreTokens()) {
                    String token = tokenizer.nextToken();
                    if (token.startsWith(">") && Domain.isValidEmail(token.substring(1))) {
                        return token.substring(1);
                    }
                }
                return null;
            }
        }
    }
    
    public static String getRecipientURLSafe(String ticket) throws ProcessException {
        if (ticket == null) {
            return null;
        } else {
            try {
                byte[] byteArray = Server.decryptToByteArrayURLSafe(ticket);
                if (byteArray.length > 8) {
                    long date = byteArray[7] & 0xFF;
                    date <<= 8;
                    date += byteArray[6] & 0xFF;
                    date <<= 8;
                    date += byteArray[5] & 0xFF;
                    date <<= 8;
                    date += byteArray[4] & 0xFF;
                    date <<= 8;
                    date += byteArray[3] & 0xFF;
                    date <<= 8;
                    date += byteArray[2] & 0xFF;
                    date <<= 8;
                    date += byteArray[1] & 0xFF;
                    date <<= 8;
                    date += byteArray[0] & 0xFF;
                    if (System.currentTimeMillis() - date > 432000000) {
                        return null;
                    } else {
                        String query = Core.decodeHuffman(byteArray, 8);
                        StringTokenizer tokenizer = new StringTokenizer(query, " ");
                        while (tokenizer.hasMoreTokens()) {
                            String token = tokenizer.nextToken();
                            if (token.startsWith(">")) {
                                token = token.substring(1);
                                if (Domain.isValidEmail(token)) {
                                    return token;
                                }
                            }
                        }
                        return null;
                    }
                } else {
                    return null;
                }
            } catch (ProcessException ex) {
                return null;
            }
        }
    }
    
    public static String getClientURLSafe(String ticket) {
        if (ticket == null) {
            return null;
        } else {
            try {
                byte[] byteArray = Server.decryptToByteArrayURLSafe(ticket);
                if (byteArray.length > 8) {
                    long date = byteArray[7] & 0xFF;
                    date <<= 8;
                    date += byteArray[6] & 0xFF;
                    date <<= 8;
                    date += byteArray[5] & 0xFF;
                    date <<= 8;
                    date += byteArray[4] & 0xFF;
                    date <<= 8;
                    date += byteArray[3] & 0xFF;
                    date <<= 8;
                    date += byteArray[2] & 0xFF;
                    date <<= 8;
                    date += byteArray[1] & 0xFF;
                    date <<= 8;
                    date += byteArray[0] & 0xFF;
                    if (System.currentTimeMillis() - date > 432000000) {
                        return null;
                    } else {
                        String query = Core.decodeHuffman(byteArray, 8);
                        StringTokenizer tokenizer = new StringTokenizer(query, " ");
                        while (tokenizer.hasMoreTokens()) {
                            String token = tokenizer.nextToken();
                            if (token.endsWith(":")) {
                                int endIndex = token.length() - 1;
                                token = token.substring(0, endIndex);
                                if (Domain.isValidEmail(token)) {
                                    return token;
                                }
                            }
                        }
                        return null;
                    }
                } else {
                    return null;
                }
            } catch (ProcessException ex) {
                return null;
            }
        }
    }

    public static String getClient(String ticket) throws ProcessException {
        if (ticket == null) {
            return null;
        } else {
            String registry = Server.decrypt(ticket);
            int index = registry.indexOf(' ');
            Date date = getTicketDate(registry.substring(0, index));
            if (System.currentTimeMillis() - date.getTime() > 432000000) {
                // Ticket vencido com mais de 5 dias.
                throw new ProcessException("TICKET EXPIRED");
            } else {
                registry = registry.substring(index + 1);
                StringTokenizer tokenizer = new StringTokenizer(registry, " ");
                while (tokenizer.hasMoreTokens()) {
                    String token = tokenizer.nextToken();
                    if (token.endsWith(":")) {
                        int end = token.length() - 1;
                        token = token.substring(0, end);
                        if (Domain.isValidEmail(token)) {
                            return token;
                        }
                    }
                }
                return null;
            }
        }
    }

    public static String getSender(String ticket) throws ProcessException {
        if (ticket == null) {
            return null;
        } else {
            String registry = Server.decrypt(ticket);
            int index = registry.indexOf(' ');
            Date date = getTicketDate(registry.substring(0, index));
            if (System.currentTimeMillis() - date.getTime() > 432000000) {
                // Ticket vencido com mais de 5 dias.
                throw new ProcessException("TICKET EXPIRED");
            } else {
                registry = registry.substring(index + 1);
                StringTokenizer tokenizer = new StringTokenizer(registry, " ");
                while (tokenizer.hasMoreTokens()) {
                    String token = tokenizer.nextToken();
                    if (token.startsWith("@") && Domain.isHostname(token.substring(1))) {
                        return token;
                    } else if (Domain.isMailFrom(token)) {
                        return token;
                    }
                }
                return null;
            }
        }
    }

    public static TreeSet<String> getTokenSet(String ticket) throws ProcessException {
        String registry = Server.decrypt(ticket);
        int index = registry.indexOf(' ');
        Date date = getTicketDate(registry.substring(0, index));
        if (System.currentTimeMillis() - date.getTime() > 432000000) {
            // Ticket vencido com mais de 5 dias.
            throw new ProcessException("TICKET EXPIRED");
        } else {
            TreeSet<String> tokenSet = new TreeSet<>();
            registry = registry.substring(index + 1);
            StringTokenizer tokenizer = new StringTokenizer(registry, " ");
            while (tokenizer.hasMoreTokens()) {
                String token = tokenizer.nextToken();
                if (isValidReputation(token)) {
                    tokenSet.add(token);
                }
            }
            return tokenSet;
        }
    }
    
    public static boolean isValidReputation(String token) {
        if (token == null || token.length() == 0) {
            return false;
        } else if (Subnet.isValidIP(token)) {
            return !Subnet.isReservedIP(token);
        } else if (token.startsWith(".") && Domain.isHostname(token.substring(1))) {
            return true;
        } else if (token.contains("@") && Domain.isMailFrom(token)) {
            return true;
        } else if (token.startsWith("@") && Domain.containsDomain(token.substring(1))) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Processa a consulta e retorna o resultado.
     *
     * @param query a expressão da consulta.
     * @return o resultado do processamento.
     */
    protected static String processSPF(
            InetAddress ipAddress,
            Client client,
            User user,
            String query,
            LinkedList<User> userList
    ) {
        try {
            String result = "";
            if (query.length() == 0) {
                return "INVALID QUERY\n";
            } else {
                String origin;
                if (client == null) {
                    origin = ipAddress.getHostAddress();
                } else if (client.hasEmail()) {
                    origin = ipAddress.getHostAddress() + " " + client.getDomain() + " " + client.getEmail();
                } else {
                    origin = ipAddress.getHostAddress() + " " + client.getDomain();
                }
                StringTokenizer tokenizer = new StringTokenizer(query, " ");
                String firstToken = tokenizer.nextToken();
                if (firstToken.equals("SPAM") && tokenizer.countTokens() == 1) {
                    String ticket = tokenizer.nextToken();
                    TreeSet<String> tokenSet = addComplainURLSafe(origin, ticket, null);
                    if (tokenSet == null) {
                        result = "DUPLICATE COMPLAIN\n";
                    } else {
                        String userEmail;
                        try {
                            userEmail = SPF.getClientURLSafe(ticket);
                        } catch (Exception ex) {
                            userEmail = client == null ? null : client.getEmail();
                        }
                        user = User.get(userEmail);
                        if (user != null) {
                            userList.add(user);
                        }
                        String recipient;
                        try {
                            recipient = SPF.getRecipientURLSafe(ticket);
                        } catch (ProcessException ex) {
                            recipient = null;
                        }
                        result = "OK " + tokenSet + (recipient == null ? "" : " >" + recipient) + "\n";
                    }
                } else if (firstToken.equals("ABUSE") && tokenizer.hasMoreTokens()) {
                    String token = tokenizer.nextToken();
                    if (token.startsWith("In-Reply-To:") && tokenizer.countTokens() == 1) {
                        token = tokenizer.nextToken();
                        if (token.startsWith("From:")) {
                            int index = token.indexOf(':') + 1;
                            String recipient = token.substring(index);
                            User recipientUser = User.get(recipient);
                            if (recipientUser == null) {
                                // Se a consulta originar de destinatário com postmaster cadastrado,
                                // considerar o próprio postmaster como usuário da consulta.
                                index = recipient.indexOf('@');
                                String postmaster = "postmaster" + recipient.substring(index);
                                User postmasterUser = User.get(postmaster);
                                if (postmasterUser != null) {
                                    userList.add(user = postmasterUser);
                                }
                            } else {
                                userList.add(user = recipientUser);
                            }
                            if (user == null) {
                                result = "UNDEFINED USER\n";
                            } else {
                                index = query.indexOf(':') + 1;
                                String messageID = query.substring(index);
                                result = "INVALID ID\n";
                                index = messageID.indexOf('<');
                                if (index >= 0) {
                                    messageID = messageID.substring(index + 1);
                                    index = messageID.indexOf('>');
                                    if (index > 0) {
                                        messageID = messageID.substring(0, index);
                                        result = user.blockByMessageID(messageID) + '\n';
                                    }
                                }
                            }
                        } else {
                            result = "INVALID FROM\n";
                        }
                    } else if (Subnet.isValidIP(token) && tokenizer.countTokens() == 0) {
                        if (SPF.addComplain(token)) {
                            Analise.processToday(token);
                            result = "COMPLAINED " + Subnet.normalizeIP(token) + "\n";
                        } else {
                            result = "NOT COMPLAINED\n";
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (firstToken.equals("HOLDING") && tokenizer.countTokens() == 1) {
                    String ticket = tokenizer.nextToken();
                    result = getHoldStatus(client, ticket, userList) + '\n';
                } else if (firstToken.equals("LINK") && tokenizer.hasMoreTokens()) {
                    String ticketSet = tokenizer.nextToken();
                    TreeSet<String> linkSet = new TreeSet<>();
                    while (tokenizer.hasMoreTokens()) {
                        linkSet.add(tokenizer.nextToken());
                    }
                    StringTokenizer tokenizerTicket = new StringTokenizer(ticketSet, ";");
                    String unblockURL = null;
                    Action actionBLOCK = null;
                    Action actionRED = null;
                    while (tokenizerTicket.hasMoreTokens()) {
                        String ticket = tokenizerTicket.nextToken();
                        String userEmail;
                        try {
                            userEmail = SPF.getClientURLSafe(ticket);
                        } catch (Exception ex) {
                            userEmail = client == null ? null : client.getEmail();
                        }
                        if ((user = User.get(userEmail)) != null) {
                            userList.add(user);
                            long dateTicket = SPF.getDateTicket(ticket);
                            User.Query queryTicket = user.getQuery(dateTicket);
                            if (queryTicket != null) {
                                Action actionQuery = null;
                                if (queryTicket.setLinkSet(linkSet)) {
                                    if (!queryTicket.isWhite() && queryTicket.blockKey(dateTicket)) {
                                        Server.logDebug("new BLOCK '" + queryTicket.getUserEmail() + ":" + queryTicket.getBlockKey() + "' added by LINK.");
                                    } else{
                                        queryTicket.complain(dateTicket);
                                    }
                                    actionQuery = actionBLOCK = client == null ? Action.REJECT : client.getActionBLOCK();
                                    unblockURL = queryTicket.getUnblockURL();
                                } else if (queryTicket.isAnyLinkRED()) {
                                    actionQuery = actionRED = client == null ? Action.FLAG : client.getActionRED();
                                }
                                if (actionQuery == Action.HOLD) {
                                    queryTicket.setResult("HOLD");
                                } else if (actionQuery == Action.FLAG) {
                                    queryTicket.setResult("FLAG");
                                } else if (actionQuery == Action.REJECT) {
                                    queryTicket.setResult("REJECT");
                                }
                                User.storeDB(dateTicket, queryTicket);
                            }
                        }
                    }
                    if (unblockURL != null) {
                        result = "BLOCKED " + unblockURL + "\n";
                    } else if (actionBLOCK == Action.HOLD) {
                        result = "HOLD\n";
                    } else if (actionBLOCK == Action.FLAG) {
                        result = "FLAG\n";
                    } else if (actionBLOCK == Action.REJECT) {
                        result = "REJECT\n";
                    } else if (actionRED == Action.HOLD) {
                        result = "HOLD\n";
                    } else if (actionRED == Action.FLAG) {
                        result = "FLAG\n";
                    } else if (actionRED == Action.REJECT) {
                        result = "REJECT\n";
                    } else {
                        result = "CLEAR\n";
                    }
                } else if (firstToken.equals("MALWARE") && tokenizer.hasMoreTokens()) {
                    String ticketSet = tokenizer.nextToken();
                    StringBuilder nameBuilder = new StringBuilder();
                    while (tokenizer.hasMoreTokens()) {
                        if (nameBuilder.length() > 0) {
                            nameBuilder.append(' ');
                        }
                        nameBuilder.append(tokenizer.nextToken());
                    }
                    
                    StringBuilder resultBuilder = new StringBuilder();
                    StringTokenizer ticketTokenizer = new StringTokenizer(ticketSet, ";");
                    while (ticketTokenizer.hasMoreTokens()) {
                        String ticket = ticketTokenizer.nextToken();
                        TreeSet<String> tokenSet = addComplainURLSafe(origin, ticket, null);
                        if (tokenSet == null) {
                            resultBuilder.append("DUPLICATE COMPLAIN\n");
                        } else {
                            boolean accept = false;
                            // Processar reclamação.
                            String userEmail;
                            try {
                                userEmail = SPF.getClientURLSafe(ticket);
                            } catch (Exception ex) {
                                userEmail = client == null ? null : client.getEmail();
                            }
                            user = User.get(userEmail);
                            if (user != null) {
                                userList.add(user);
                                long dateTicket = getDateTicket(ticket);
                                User.Query userQuery = user.getQuery(dateTicket);
                                String resultMalware;
                                if (userQuery != null && (resultMalware = userQuery.setMalware(nameBuilder.toString())) != null) {
                                    User.storeDB(dateTicket, userQuery);
                                    if (resultMalware.equals("ACCEPT")) {
                                        accept = true;
                                    } else if (userQuery.isWhiteKey()) {
                                        userQuery.complain(dateTicket);
                                    } else if (userQuery.blockKey(dateTicket)) {
                                        Server.logDebug("new BLOCK '" + userQuery.getUserEmail() + ":" +  userQuery.getBlockKey() + "' added by '" + userQuery.getRecipient() + ";MALWARE'.");
                                    } else {
                                        userQuery.complain(dateTicket);
                                    }
                                }
                            }
                            if (accept) {
                                resultBuilder.append("ACCEPT");
                            } else {
                                String recipient;
                                try {
                                    recipient = SPF.getRecipientURLSafe(ticket);
                                } catch (ProcessException ex) {
                                    recipient = null;
                                }
                                // Bloquear automaticamente todos
                                // os tokens com reputação amarela ou vermelha.
                                // Processar reclamação.
                                for (String token : tokenSet) {
                                    String block;
                                    Status status = SPF.getStatus(token);
                                    if (status == Status.RED && Analise.isRunning() && (block = Block.addSafe(token)) != null) {
                                        Server.logDebug("new BLOCK '" + block + "' added by '" + recipient + ";MALWARE'.");
                                        Peer.sendBlockToAll(block);
                                    }
                                    if (status != Status.GREEN && !Subnet.isValidIP(token) && (block = Block.addIfNotNull(user, token)) != null) {
                                        Server.logDebug("new BLOCK '" + block + "' added by '" + recipient + ";MALWARE'.");
                                    }
                                }
                                resultBuilder.append("OK ");
                                resultBuilder.append(tokenSet);
                                resultBuilder.append(recipient == null ? "" : " >" + recipient);
                            }
                            resultBuilder.append("\n");
                        }
                    }
                    result = resultBuilder.toString();
                } else if (firstToken.equals("BODY") && tokenizer.countTokens() == 2) {
                    String ticketSet = tokenizer.nextToken();
                    byte[] data = Core.BASE64.decode(tokenizer.nextToken());
                    if (data.length > 65535) {
                        result = "TOO BIG\n";
                    } else {
                        TreeMap<Long,Query> queryMap = new TreeMap<>();
                        StringTokenizer ticketTokenizer = new StringTokenizer(ticketSet, ";");
                        while (ticketTokenizer.hasMoreTokens()) {
                            String ticket = ticketTokenizer.nextToken();
                            Entry<Long,Query> entry = User.getQueryEntry(ticket);
                            if (entry != null) {
                                long timeTicket = entry.getKey();
                                Query queryTicket = entry.getValue();
                                queryMap.put(timeTicket, queryTicket);
                            }
                        }
                        if (queryMap.isEmpty()) {
                            result = "NOT FOUND\n";
                        } else {
                            for (long time : queryMap.keySet()) {
                                Query queryTicket = queryMap.get(time);
                                queryTicket.setBody(data);
                                User.storeDB(time, queryTicket);
                            }
                            result = "CHANGED\n";
                        }
                    }
                } else if (firstToken.equals("HEADER") && tokenizer.hasMoreTokens()) {
                    String ticketSet = tokenizer.nextToken();
                    String key = null;
                    String from = null;
                    String replyto = null;
                    String messageID = null;
                    String unsubscribe = null;
                    String subject = null;
                    String date = null;
                    while (tokenizer.hasMoreTokens()) {
                        String token = tokenizer.nextToken();
                        if (token.startsWith("From:")) {
                            key = "From";
                            int index = token.indexOf(':');
                            from = token.substring(index+1);
                        } else if (token.startsWith("ReplyTo:") || token.startsWith("Reply-To:")) {
                            key = "Reply-To";
                            int index = token.indexOf(':');
                            replyto = token.substring(index+1);
                        } else if (token.startsWith("Message-ID:")) {
                            key = "Message-ID";
                            int index = token.indexOf(':');
                            messageID = token.substring(index+1);
                        } else if (token.startsWith("List-Unsubscribe:")) {
                            key = "List-Unsubscribe";
                            int index = token.indexOf(':');
                            unsubscribe = token.substring(index+1);
                        } else if (token.startsWith("Subject:")) {
                            key = "Subject";
                            int index = token.indexOf(':');
                            subject = token.substring(index+1);
                        } else if (token.startsWith("Date:")) {
                            key = "Date";
                            int index = token.indexOf(':');
                            date = token.substring(index+1);
                        } else if (key == null) {
                            from = null;
                            replyto = null;
                            unsubscribe = null;
                            subject = null;
                            date = null;
                            break;
                        } else if (key.equals("From")) {
                            from += ' ' + token;
                        } else if (key.equals("Reply-To")) {
                            replyto += ' ' + token;
                        } else if (key.equals("Message-ID")) {
                            messageID += ' ' + token;
                        } else if (key.equals("List-Unsubscribe")) {
                            unsubscribe += ' ' + token;
                        } else if (key.equals("Subject")) {
                            subject += ' ' + token;
                        } else if (key.equals("Date")) {
                            date += ' ' + token;
                        }
                    }
                    if (
                            (from == null || from.length() == 0) &&
                            (replyto == null || replyto.length() == 0) &&
                            (messageID == null || messageID.length() == 0) &&
                            (unsubscribe == null || unsubscribe.length() == 0) &&
                            (subject == null || subject.length() == 0) &&
                            (date == null || date.length() == 0)
                            ) {
                        result = "INVALID COMMAND\n";
                    } else {
                        boolean whitelisted = false;
                        boolean blocklisted = false;
                        boolean hold = false;
                        boolean flag = false;
                        boolean reject = false;
                        TreeSet<String> unblockURLSet = new TreeSet<>();
                        StringTokenizer ticketTokenizer = new StringTokenizer(ticketSet, ";");
                        int n = ticketTokenizer.countTokens();
                        ArrayList<User.Query> queryList = new ArrayList<>(n);
                        while (ticketTokenizer.hasMoreTokens()) {
                            String ticket = ticketTokenizer.nextToken();
                            String userEmail;
                            try {
                                userEmail = SPF.getClientURLSafe(ticket);
                            } catch (Exception ex) {
                                userEmail = client == null ? null : client.getEmail();
                            }
                            if ((user = User.get(userEmail)) != null) {
                                userList.add(user);
                                long dateTicket = SPF.getDateTicket(ticket);
                                User.Query queryTicket = user.getQuery(dateTicket);
                                if (queryTicket != null) {
                                    queryList.add(queryTicket);
                                    Action actionRED = client == null ? Action.FLAG : client.getActionRED();
                                    Action actionBLOCK = client == null ? Action.REJECT : client.getActionBLOCK();
                                    String resultLocal = queryTicket.setHeader(
                                            dateTicket, client, from, replyto,
                                            subject, messageID,
                                            date, unsubscribe, actionBLOCK, actionRED
                                    );
                                    if ("WHITE".equals(resultLocal)) {
                                        whitelisted = true;
                                    } else if ("FLAG".equals(resultLocal)) {
                                        flag = true;
                                    } else if ("HOLD".equals(resultLocal)) {
                                        hold = true;
                                    } else if ("BLOCK".equals(resultLocal)) {
                                        blocklisted = true;
                                        String url = queryTicket.getUnblockURL();
                                        if (url != null) {
                                            unblockURLSet.add(url);
                                        }
                                    } else if ("REJECT".equals(resultLocal)) {
                                        reject = true;
                                    }
                                    User.storeDB(dateTicket, queryTicket);
                                }
                            }
                        }
                        if (whitelisted) {
                            for (User.Query queryTicket : queryList) {
                                queryTicket.setResult("WHITE");
                            }
                            result = "WHITE\n";
                        } else if (blocklisted) {
                            for (User.Query queryTicket : queryList) {
                                queryTicket.setResult("BLOCK");
                            }
                            if (unblockURLSet.size() == 1) {
                                result = "BLOCKED " + unblockURLSet.first() + "\n";
                            } else {
                                result = "BLOCKED\n";
                            }
                        } else if (reject) {
                            result = "REJECT\n";
                        } else if (hold) {
                            result = "HOLD\n";
                        } else if (flag) {
                            result = "FLAG\n";
                        } else {
                            result = "CLEAR\n";
                        }
                    }
                } else if (firstToken.equals("HAM") && tokenizer.countTokens() == 1) {
                    String ticket = tokenizer.nextToken();
                    TreeSet<String> tokenSet = deleteComplainURLSafe(origin, ticket);
                    if (tokenSet == null) {
                        result = "ALREADY REMOVED\n";
                    } else {
                        String recipient;
                        try {
                            recipient = SPF.getRecipientURLSafe(ticket);
                        } catch (ProcessException ex) {
                            recipient = null;
                        }
                        result = "OK " + tokenSet + (recipient == null ? "" : " >" + recipient) + "\n";
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
                        || (firstToken.equals("CHECK") && tokenizer.countTokens() == 4)
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
                            if (recipient.equals("'")) {
                                recipient = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : "";
                                if (recipient.endsWith("'")) {
                                    recipient = recipient.substring(0, recipient.length() - 1);
                                }
                            } else {
                                recipient = recipient.substring(1, recipient.length() - 1);
                            }
                            if (sender.length() == 0) {
                                sender = null;
                            } else {
                                sender = sender.toLowerCase();
                            }
                            recipient = recipient.toLowerCase();
                            recipient = recipient.replace("\"", "");
                        } else if (firstToken.equals("CHECK") && tokenizer.countTokens() == 4) {
                            ip = tokenizer.nextToken().toLowerCase();
                            sender = tokenizer.nextToken().toLowerCase();
                            helo = tokenizer.nextToken();
                            recipient = tokenizer.nextToken().toLowerCase();
                            if (ip.startsWith("'") && ip.endsWith("'")) {
                                ip = ip.substring(1, ip.length() - 1);
                            }
                            if (sender.startsWith("'") && sender.endsWith("'")) {
                                sender = sender.substring(1, sender.length() - 1);
                            }
                            if (helo.startsWith("'") && helo.endsWith("'")) {
                                helo = helo.substring(1, helo.length() - 1);
                            }
                            if (recipient.startsWith("'") && recipient.endsWith("'")) {
                                recipient = recipient.substring(1, recipient.length() - 1);
                            }
                            if (ip.length() == 0) {
                                ip = null;
                            }
                            if (sender.length() == 0) {
                                sender = null;
                            }
                            if (!Domain.isHostname(helo)) {
                                helo = null;
                            }
                            if (recipient.length() == 0) {
                                recipient = null;
                            } else {
                                recipient = recipient.toLowerCase();
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
                                helo = tokenizer.nextToken();
                            } else {
                                sender = null;
                                helo = tokenizer.nextToken();
                            }
                            recipient = null;
                            if (ip.startsWith("'") && ip.endsWith("'")) {
                                ip = ip.substring(1, ip.length() - 1);
                            }
                            if (sender != null && sender.startsWith("'") && sender.endsWith("'")) {
                                sender = sender.substring(1, sender.length() - 1);
                                if (sender.length() == 0) {
                                    sender = null;
                                }
                            }
                            if (helo.startsWith("'") && helo.endsWith("'")) {
                                helo = helo.substring(1, helo.length() - 1);
                            }
                        }
                        ip = SubnetIPv6.tryTransformToIPv4(ip);
                        if (!Subnet.isValidIP(ip)) {
                            return "INVALID\n";
                        } else if (sender != null && !Domain.isMailFrom(sender)) {
                            return "INVALID\n";
                        } else if (recipient != null && !Domain.isValidEmail(recipient)) {
                            return "INVALID\n";
                        } else if (Subnet.isReservedIP(ip)) {
                            // Message from LAN.
                            return "LAN\n";
                        } else if (client != null && client.containsFull(ip)) {
                            // Message from LAN.
                            return "LAN\n";
                        } else {
                            TreeSet<String> tokenSet = new TreeSet<>();
                            ip = Subnet.normalizeIP(ip);
                            tokenSet.add(ip);
                            if (Domain.isValidEmail(recipient)) {
                                // Se houver um remetente válido,
                                // Adicionar no ticket para controle.
                                tokenSet.add('>' + recipient);
                            }
                            if (recipient != null) {
                                User recipientUser = User.get(recipient);
                                if (recipientUser == null) {
                                    // Se a consulta originar de destinatário com postmaster cadastrado,
                                    // considerar o próprio postmaster como usuário da consulta.
                                    int index = recipient.indexOf('@');
                                    String postmaster = "postmaster" + recipient.substring(index);
                                    User postmasterUser = User.get(postmaster);
                                    if (postmasterUser != null) {
                                        user = postmasterUser;
                                    }
                                } else {
                                    user = recipientUser;
                                }
                            }
                            if (user != null) {
                                userList.add(user);
                                tokenSet.add(user.getEmail() + ':');
                            } else if (client != null && client.hasEmail()) {
                                tokenSet.add(client.getEmail() + ':');
                            }
                            // Passar a acompanhar todos os 
                            // HELO quando apontados para o IP para 
                            // uma nova forma de interpretar dados.
                            String hostname;
                            if (CacheHELO.match(ip, helo, false)) {
                                hostname = Domain.normalizeHostname(helo, true);
                            } else {
                                hostname = Reverse.getHostname(ip);
                                hostname = Domain.normalizeHostname(hostname, true);
                            }
                            if (White.isDesactive(client, user, ip, hostname, recipient)) {
                                // SPFBL desactived for this case.
                                return "LAN\n";
                            } else if (hostname == null) {
                                Server.logDebug("no rDNS for " + ip + ".");
                            } else if (Domain.isOfficialTLD(hostname)) {
                                return "INVALID\n";
                            } else {
                                // Verificação de pilha dupla,
                                // para pontuação em ambas pilhas.
                                String ipv4 = CacheHELO.getUniqueIPv4(hostname);
                                String ipv6 = CacheHELO.getUniqueIPv6(hostname);
                                if (ip.equals(ipv6) && CacheHELO.match(ipv4, hostname, false)) {
                                    // Equivalência de pilha dupla se 
                                    // IPv4 for único para o hostname.
                                    tokenSet.add(ipv4);
                                } else if (ip.equals(ipv4) && CacheHELO.match(ipv6, hostname, false)) {
                                    // Equivalência de pilha dupla se 
                                    // IPv6 for único para o hostname.
                                    tokenSet.add(ipv6);
                                }
                            }
                            if (Generic.containsGenericSoft(hostname)) {
                                // Quando o reverso for 
                                // genérico, não considerá-lo.
                                hostname = null;
                            } else if (hostname != null) {
                                tokenSet.add(hostname);
                            }
                            LinkedList<String> logList = null;
                            if (sender != null && firstToken.equals("CHECK")) {
                                int index = sender.lastIndexOf('@');
                                String domain = sender.substring(index + 1);
                                logList = new LinkedList<>();
                                try {
                                    CacheSPF.refresh(domain, false);
                                } catch (ProcessException ex) {
                                    logList.add("Cannot refresh SPF registry: " + ex.getErrorMessage());
                                    logList.add("Using cached SPF registry.");
                                }
                            }
                            SPF spf;
                            if (sender == null) {
                                spf = null;
                                result = "NONE";
                            } else if (Domain.isOfficialTLD(sender)) {
                                spf = null;
                                result = "NONE";
                            } else if (Generic.containsGeneric(sender)) {
                                spf = null;
                                result = "NONE";
                            } else if ((spf = CacheSPF.get(sender)) == null) {
                                result = "NONE";
                            } else if (spf.isInexistent()) {
                                result = "NONE";
                            } else {
                                result = spf.getResult(ip, sender, helo, logList);
                            }
                            String mx = Domain.extractHost(sender, true);
//                            if (user != null && user.isLocal()) {
//                                // Message from local user.
//                                return "LAN\n";
//                            } else
                            if (recipient != null && result.equals("PASS")) {
                                if (recipient.endsWith(mx)) {
                                    // Message from same domain.
                                    return "LAN\n";
                                } else if (
                                        recipient.equals(Core.getAbuseEmail()) &&
                                        User.exists(sender, "postmaster" + mx)
                                        ) {
                                    // Message to abuse.
                                    return "LAN\n";
                                }
                            }
                            if (result.equals("PASS") || (sender != null && Provider.containsHELO(ip, hostname))) {
                                // Quando fo PASS, significa que o domínio
                                // autorizou envio pelo IP, portanto o dono dele
                                // é responsavel pelas mensagens.
                                if (!Provider.containsExact(mx)) {
                                    // Não é um provedor então
                                    // o MX deve ser listado.
                                    tokenSet.add(mx);
                                    origem = mx;
                                } else if (Domain.isValidEmail(sender)) {
                                    // Listar apenas o remetente se o
                                    // hostname for um provedor de e-mail.
                                    String userEmail = null;
                                    String recipientEmail = null;
                                    for (String token : tokenSet) {
                                        if (token.endsWith(":")) {
                                            userEmail = token;
                                        } else if (token.startsWith(">")) {
                                            recipientEmail = token;
                                        }
                                    }
                                    tokenSet.clear();
                                    tokenSet.add(sender);
                                    if (userEmail != null) {
                                        tokenSet.add(userEmail);
                                    }
                                    if (recipientEmail != null) {
                                        tokenSet.add(recipientEmail);
                                    }
                                    origem = sender;
                                } else {
                                    origem = sender;
                                }
                                fluxo = origem + ">" + recipient;
                            } else if (hostname == null) {
                                origem = (sender == null ? "" : sender + '>') + ip;
                                fluxo = origem + ">" + recipient;
                            } else {
                                String dominio = Domain.extractDomain(hostname, true);
                                origem = (sender == null ? "" : sender + '>') + (dominio == null ? hostname : dominio.substring(1));
                                fluxo = origem + ">" + recipient;
                            }
                            Long recipientTrapTime = Trap.getTimeRecipient(client, user, recipient);
                            if (firstToken.equals("CHECK")) {
                                String results = "\nClient: " + (client == null ? ipAddress.getHostAddress() : client);
                                results += "\nUser: " + (user == null ? "NOT DEFINED" : user);
                                results += "\n\nSPF resolution results:\n";
                                if (spf != null && spf.isInexistent()) {
                                    results += "   NXDOMAIN\n";
                                } else if (logList == null || logList.isEmpty()) {
                                    results += "   NONE\n";
                                } else {
                                    for (String log : logList) {
                                        results += "   " + log + "\n";
                                    }
                                }
                                String white;
                                if ((white = White.find(client, user, ip, sender, hostname, result, recipient)) != null) {
                                    results += "\nFirst WHITE match: " + white + "\n";
                                } else {
                                    String block;
                                    if ((block = Block.find(client, user, ip, sender, hostname, result, recipient, false, true, true, false)) != null) {
                                        results += "\nFirst BLOCK match: " + block + "\n";
                                    }
                                    results += "\nRecommended WHITE key: " + White.key(client, user, ip, sender, hostname, result) + "\n";
                                }
                                
                                TreeSet<String> graceSet = new TreeSet<>();
                                if (Domain.isGraceTime(sender)) {
                                    graceSet.add(Domain.extractDomain(sender, false));
                                }
                                if (Domain.isGraceTime(hostname)) {
                                    graceSet.add(Domain.extractDomain(hostname, false));
                                }
                                if (!graceSet.isEmpty()) {
                                    results += "\n";
                                    results += "Domains in grace time:\n";
                                    for (String grace : graceSet) {
                                        results += "   " + grace + "\n";
                                    }
                                }
                                results += "\n";
                                results += "Considered identifiers and status:\n";
                                tokenSet = expandTokenSet(tokenSet);
                                TreeMap<String,Distribution> distributionMap = CacheDistribution.getMap(tokenSet);
                                int count = 0;
                                for (String token : tokenSet) {
                                    if (!token.startsWith(">") && !token.endsWith(":")) {
                                        if (!Ignore.contains(token)) {
                                            float probability;
                                            Status status;
                                            if (distributionMap.containsKey(token)) {
                                                Distribution distribution = distributionMap.get(token);
                                                probability = distribution.getSpamProbability(token);
                                                status = distribution.getStatus(token);
                                            } else {
                                                probability = 0.0f;
                                                status = SPF.Status.GREEN;
                                            }
                                            results += "   " + token
                                                    + " " + status.name() + " "
                                                    + Core.DECIMAL_FORMAT.format(probability) + "\n";
                                            count++;
                                        }
                                    }
                                }
                                if (count == 0) {
                                    results += "   NONE\n";
                                }
                                results += "\n";
                                return results;
                            } else if (recipientTrapTime == null && White.contains(client, user, ip, sender, hostname, result, recipient)) {
//                                if (user != null) {
                                    if (White.contains(client, user, ip, sender, hostname, result, null)) {
                                        // Limpa da lista BLOCK um possível falso positivo.
                                        Block.clear(client, user, ip, sender, hostname, result, null);
                                    }
//                                }
                                // Calcula frequencia de consultas.
                                String url = Core.getURL(user);
                                String ticket = SPF.addQueryHam(
                                        client, user, ip, helo, hostname, sender,
                                        result, recipient, tokenSet, "WHITE"
                                );
                                return "WHITE " + (url == null ? ticket : url + ticket) + "\n";
                            } else if (Block.contains(client, user, ip, sender, hostname, result, recipient, true, true, true, true)) {
                                if (recipientTrapTime == null) {
                                    Action action = client == null ? Action.REJECT : client.getActionBLOCK();
                                    if (action == Action.REJECT) {
                                        // Calcula frequencia de consultas.
                                        Object[] resultSet = SPF.addQuerySpam(
                                                client, user, ip, helo, hostname, sender,
                                                result, recipient, tokenSet, "BLOCK"
                                        );
                                        long time = resultSet == null ? Server.getNewUniqueTime() : (Long) resultSet[0];
                                        User.Query queryLocal = resultSet == null ? null : (User.Query) resultSet[1];
                                        if (queryLocal != null && queryLocal.needHeader()) {
                                            action = client == null ? Action.FLAG : client.getActionRED();
                                            if (action == Action.HOLD) {
                                                queryLocal.setResult("HOLD");
                                                String url = Core.getURL(user);
                                                String ticket = SPF.createTicket(time, tokenSet);
                                                return "HOLD " + (url == null ? ticket : url + ticket) + "\n";
                                            } else {
                                                queryLocal.setResult("FLAG");
                                                String url = Core.getURL(user);
                                                String ticket = SPF.createTicket(time, tokenSet);
                                                return "FLAG " + (url == null ? ticket : url + ticket) + "\n";
                                            }
                                        } else {
                                            String url = Core.getUnblockURL(
                                                    client, user, ip,
                                                    sender, hostname, recipient
                                            );
                                            if (url == null) {
                                                return "BLOCKED\n";
                                            } else {
                                                return "BLOCKED " + url + "\n";
                                            }
                                        }
                                    } else if (action == Action.FLAG) {
                                        String url = Core.getURL(user);
                                        String ticket = SPF.getTicket(
                                                client, user, ip, helo, hostname, sender,
                                                result, recipient, tokenSet, "FLAG"
                                        );
                                        return "FLAG " + (url == null ? ticket : url + ticket) + "\n";
                                    } else if (action == Action.HOLD) {
                                        String url = Core.getURL(user);
                                        String ticket = SPF.getTicket(
                                                client, user, ip, helo, hostname, sender,
                                                result, recipient, tokenSet, "HOLD"
                                        );
                                        return "HOLD " + (url == null ? ticket : url + ticket) + "\n";
                                    } else {
                                        return "ERROR: UNDEFINED ACTION\n";
                                    }
                                } else {
                                    Object[] resultSet = SPF.addQuerySpam(
                                            client, user, ip, helo, hostname, sender,
                                            result, recipient, tokenSet, "BLOCK"
                                    );
                                    long time = resultSet == null ? Server.getNewUniqueTime() : (Long) resultSet[0];
                                    User.Query queryLocal = resultSet == null ? null : (User.Query) resultSet[1];
                                    if (queryLocal != null && queryLocal.blockKey(time)) {
                                        Server.logDebug("new BLOCK '" + queryLocal.getUserEmail() + ":" + queryLocal.getBlockKey() + "' added by '" + recipient + ";INEXISTENT'.");
                                    }
                                    String url = Core.getUnblockURL(
                                            client, user, ip,
                                            sender, hostname, recipient
                                    );
                                    if (url == null) {
                                        return "BLOCKED\n";
                                    } else {
                                        return "BLOCKED " + url + "\n";
                                    }
                                }
                            } else if (Generic.containsDynamicDomain(hostname)) {
                                // Bloquear automaticamente range de IP dinâmico.
                                if (Analise.isRunning()) {
                                    String cidr = Subnet.normalizeCIDR(SubnetIPv4.isValidIPv4(ip) ? ip + "/24" : ip + "/48");
                                    if (Block.tryOverlap(cidr)) {
                                        Server.logDebug("new BLOCK '" + cidr + "' added by '" + hostname + ";DYNAMIC'.");
                                    } else if (Block.tryAdd(ip)) {
                                        Server.logDebug("new BLOCK '" + ip + "' added by '" + hostname + ";DYNAMIC'.");
                                    }
                                }
                                SPF.addQuerySpam(
                                        client, user, ip, helo, hostname, sender,
                                        result, recipient, tokenSet, "INVALID"
                                );
                                return "INVALID\n";
                            } else if (spf != null && spf.isDefinitelyInexistent()) {
                                // Bloquear automaticamente IP com reputação vermelha.
                                if (Analise.isRunning() && SPF.isRed(ip)) {
                                    if (Block.tryAdd(ip)) {
                                        Server.logDebug("new BLOCK '" + ip + "' added by '" + mx + ";NXDOMAIN'.");
                                    }
                                }
                                Analise.processToday(ip);
                                // O domínio foi dado como inexistente inúmeras vezes.
                                // Rejeitar e denunciar o host pois há abuso de tentativas.
                                SPF.addQuerySpam(
                                        client, user, ip, helo, hostname, sender,
                                        result, recipient, tokenSet, "NXDOMAIN"
                                );
                                return "NXDOMAIN\n";
                            } else if (spf != null && spf.isInexistent()) {
                                Analise.processToday(ip);
                                SPF.addQuery(
                                        client, user, ip, helo, hostname, sender,
                                        result, recipient, tokenSet, "GREYLIST"
                                );
                                return "GREYLIST\n";
                            } else if (result.equals("FAIL")) {
                                // Bloquear automaticamente IP com reputação vermelha.
                                if (Analise.isRunning() && SPF.isRed(ip)) {
                                    if (Block.tryAdd(ip)) {
                                        Server.logDebug("new BLOCK '" + ip + "' added by '" + sender + ";FAIL'.");
                                    }
                                }
                                Analise.processToday(ip);
                                SPF.addQuerySpam(
                                        client, user, ip, helo, hostname, sender,
                                        result, recipient, tokenSet, "FAIL"
                                );
                                // Retornar FAIL somente se não houver 
                                // liberação literal do remetente com FAIL.
                                return "FAIL\n";
                            } else if (sender != null && !Domain.isMailFrom(sender)) {
                                // Bloquear automaticamente IP com reputação vermelha.
                                if (Analise.isRunning() && SPF.isRed(ip)) {
                                    if (Block.tryAdd(ip)) {
                                        Server.logDebug("new BLOCK '" + ip + "' added by '" + sender + ";INVALID'.");
                                    }
                                }
                                Analise.processToday(ip);
                                SPF.addQuerySpam(
                                        client, user, ip, helo, hostname, sender,
                                        result, recipient, tokenSet, "INVALID"
                                );
                                return "INVALID\n";
                            } else if (sender != null && Domain.isOfficialTLD(sender)) {
                                // Bloquear automaticamente IP com reputação vermelha.
                                if (Analise.isRunning() && SPF.isRed(ip)) {
                                    if (Block.tryAdd(ip)) {
                                        Server.logDebug("new BLOCK '" + ip + "' added by '" + sender + ";RESERVED'.");
                                    }
                                }
                                Analise.processToday(ip);
                                SPF.addQuerySpam(
                                        client, user, ip, helo, hostname, sender,
                                        result, recipient, tokenSet, "INVALID"
                                );
                                return "INVALID\n";
                            } else if (sender == null && !CacheHELO.match(ip, hostname, false)) {
                                // Bloquear automaticamente IP com reputação ruim.
                                if (Analise.isRunning() && SPF.isRed(ip)) {
                                    if (Block.tryAdd(ip)) {
                                        Server.logDebug("new BLOCK '" + ip + "' added by 'INVALID'.");
                                    }
                                }
                                Analise.processToday(ip);
                                SPF.addQuerySpam(
                                        client, user, ip, helo, hostname, sender,
                                        result, recipient, tokenSet, "INVALID"
                                );
                                // HELO inválido sem remetente.
                                return "INVALID\n";
                            } else if (hostname == null && Core.isReverseRequired()) {
                                if (Analise.isRunning() && Block.tryAdd(ip)) {
                                    Server.logDebug("new BLOCK '" + ip + "' added by 'NONE'.");
                                }
                                Analise.processToday(ip);
                                SPF.addQuerySpam(
                                        client, user, ip, helo, hostname, sender,
                                        result, recipient, tokenSet, "INVALID"
                                );
                                // Require a valid HELO or reverse.
                                return "INVALID\n";
                            } else if (recipient != null && !Domain.isValidEmail(recipient)) {
                                Analise.processToday(ip);
                                Analise.processToday(mx);
                                SPF.getTicket(
                                        client, user, ip, helo, hostname, sender,
                                        result, recipient, tokenSet, "INEXISTENT"
                                );
                                return "INEXISTENT\n";
                            } else if (recipientTrapTime != null) {
                                if (System.currentTimeMillis() > recipientTrapTime) {
                                    // Spamtrap
                                    if (Analise.isRunning()) {
                                        for (String token : tokenSet) {
                                            String block;
                                            Status status = SPF.getStatus(token);
                                            if (status == Status.RED && Analise.isRunning() && (block = Block.addSafe(token)) != null) {
                                                Server.logDebug("new BLOCK '" + block + "' added by '" + recipient + ";SPAMTRAP'.");
                                                Peer.sendBlockToAll(block);
                                            }
                                            if (status != Status.GREEN && !Subnet.isValidIP(token) && (block = Block.addIfNotNull(user, token)) != null) {
                                                Server.logDebug("new BLOCK '" + block + "' added by '" + recipient + ";SPAMTRAP'.");
                                            }
                                        }
                                        Analise.processToday(ip);
                                        Analise.processToday(mx);
                                    }
                                    // Calcula frequencia de consultas.
                                    SPF.addQuerySpam(
                                            client, user, ip, helo, hostname, sender,
                                            result, recipient, tokenSet, "TRAP"
                                    );
                                    return "SPAMTRAP\n";
                                } else {
                                    // Inexistent
                                    for (String token : tokenSet) {
                                        String block;
                                        Status status = SPF.getStatus(token);
                                        if (status == Status.RED && Analise.isRunning() && (block = Block.addSafe(token)) != null) {
                                            Server.logDebug("new BLOCK '" + block + "' added by '" + recipient + ";INEXISTENT'.");
                                            Peer.sendBlockToAll(block);
                                        }
                                        if (status != Status.GREEN && !Subnet.isValidIP(token) && (block = Block.addIfNotNull(user, token)) != null) {
                                            Server.logDebug("new BLOCK '" + block + "' added by '" + recipient + ";INEXISTENT'.");
                                        }
                                    }
                                    Analise.processToday(ip);
                                    Analise.processToday(mx);
                                    SPF.getTicket(
                                            client, user, ip, helo, hostname, sender,
                                            result, recipient, tokenSet, "INEXISTENT"
                                    );
                                    return "INEXISTENT\n";
                                }
                            } else if (result.equals("PASS") && SPF.isGood(Provider.containsExact(mx) ? sender : mx)) {
                                // O remetente é válido e tem excelente reputação,
                                // ainda que o provedor dele esteja com reputação ruim.
                                String url = Core.getURL(user);
                                String ticket = SPF.addQueryHam(
                                        client, user, ip, helo, hostname, sender,
                                        result, recipient, tokenSet, "ACCEPT"
                                );
                                return "PASS " + (url == null ? ticket : url + URLEncoder.encode(ticket, "UTF-8")) + "\n";
                            } else if (Defer.count(fluxo) > Core.getFloodMaxRetry()) {
                                Analise.processToday(ip);
                                Analise.processToday(mx);
                                // A origem atingiu o limite de atraso 
                                // para liberação do destinatário.
                                long time = System.currentTimeMillis();
                                Defer.end(fluxo);
                                Server.logDefer(time, fluxo, "DEFER FLOOD");
                                SPF.addQuerySpam(
                                        client, user, ip, helo, hostname, sender,
                                        result, recipient, tokenSet, "REJECT"
                                );
                                return "BLOCKED\n";
                            } else if (!result.equals("PASS") && !CacheHELO.match(ip, hostname, false)) {
                                // Bloquear automaticamente IP com reputação amarela.
                                if (Analise.isRunning()) {
                                    if (SPF.isRed(ip)) {
                                        if (Block.tryAdd(ip)) {
                                            Server.logDebug("new BLOCK '" + ip + "' added by '" + recipient + ";INVALID'.");
                                        }
                                    }
                                    Analise.processToday(ip);
                                }
                                SPF.addQuerySpam(
                                        client, user, ip, helo, hostname, sender,
                                        result, recipient, tokenSet, "INVALID"
                                );
                                return "INVALID\n";
                            } else if (recipient != null && recipient.startsWith("postmaster@")) {
                                String url = Core.getURL(user);
                                String ticket = SPF.getTicket(
                                        client, user, ip, helo, hostname, sender,
                                        result, recipient, tokenSet, "ACCEPT"
                                );
                                return result + " " + (url == null ? ticket : url + URLEncoder.encode(ticket, "UTF-8")) + "\n";
                            } else if (SPF.hasRed(tokenSet)) {
                                Analise.processToday(ip);
                                Analise.processToday(mx);
                                Action action = client == null ? Action.REJECT : client.getActionRED();
                                if (action == Action.REJECT) {
                                    // Calcula frequencia de consultas.
                                    SPF.addQuerySpam(
                                            client, user, ip, helo, hostname, sender,
                                            result, recipient, tokenSet, "REJECT"
                                    );
                                    return "BLOCKED\n";
                                } else if (action == Action.DEFER) {
                                    if (Defer.defer(fluxo, Core.getDeferTimeRED())) {
                                        String url = Core.getReleaseURL(user, fluxo);
                                        SPF.addQuery(
                                                client, user, ip, helo, hostname, sender,
                                                result, recipient, tokenSet, "LISTED"
                                        );
                                        if (url == null || Defer.count(fluxo) > 1) {
                                            return "LISTED\n";
                                        } else if (result.equals("PASS") && enviarLiberacao(url, sender, recipient)) {
                                            // Envio da liberação por e-mail se 
                                            // houver validação do remetente por PASS.
                                            return "LISTED\n";
                                        } else {
                                            return "LISTED " + url + "\n";
                                        }
                                    } else {
                                        // Calcula frequencia de consultas.
                                        SPF.addQuerySpam(
                                                client, user, ip, helo, hostname, sender,
                                                result, recipient, tokenSet, "REJECT"
                                        );
                                        return "BLOCKED\n";
                                    }
                                } else if (action == Action.FLAG) {
                                    String url = Core.getURL(user);
                                    String ticket = SPF.getTicket(
                                            client, user, ip, helo, hostname, sender,
                                            result, recipient, tokenSet, "FLAG"
                                    );
                                    return "FLAG " + (url == null ? ticket : url + ticket) + "\n";
                                } else if (action == Action.HOLD) {
                                    String url = Core.getURL(user);
                                    String ticket = SPF.getTicket(
                                            client, user, ip, helo, hostname, sender,
                                            result, recipient, tokenSet, "HOLD"
                                    );
                                    return "HOLD " + (url == null ? ticket : url + ticket) + "\n";
                                } else {
                                    return "ERROR: UNDEFINED ACTION\n";
                                }
                            } else if (Domain.isGraceTime(sender) || Domain.isGraceTime(hostname)) {
                                Server.logTrace("domain in grace time.");
                                for (String token : tokenSet) {
                                    String block;
                                    Status status = SPF.getStatus(token);
                                    if (status == Status.RED && Analise.isRunning() && (block = Block.addSafe(token)) != null) {
                                        Server.logDebug("new BLOCK '" + block + "' added by '" + status + "'.");
                                        Peer.sendBlockToAll(block);
                                    }
                                    if (status != Status.GREEN && !Subnet.isValidIP(token) && (block = Block.addIfNotNull(user, token)) != null) {
                                        Server.logDebug("new BLOCK '" + block + "' added by '" + status + "'.");
                                    }
                                }
                                Analise.processToday(ip);
                                Analise.processToday(mx);
                                Action action = client == null ? Action.REJECT : client.getActionGRACE();
                                if (action == Action.REJECT) {
                                    // Calcula frequencia de consultas.
                                    SPF.addQuerySpam(
                                            client, user, ip, helo, hostname, sender,
                                            result, recipient, tokenSet, "REJECT"
                                    );
                                    return "BLOCKED\n";
                                } else if (action == Action.DEFER) {
                                    if (Defer.defer(fluxo, Core.getDeferTimeYELLOW())) {
                                        SPF.addQuery(
                                                client, user, ip, helo, hostname, sender,
                                                result, recipient, tokenSet, "GREYLIST"
                                        );
                                        return "GREYLIST\n";
                                    } else {
                                        String url = Core.getURL(user);
                                        String ticket = SPF.getTicket(
                                                client, user, ip, helo, hostname, sender,
                                                result, recipient, tokenSet, "FLAG"
                                        );
                                        return "FLAG " + (url == null ? ticket : url + ticket) + "\n";
                                    }
                                } else if (action == Action.HOLD) {
                                    String url = Core.getURL(user);
                                    String ticket = SPF.getTicket(
                                            client, user, ip, helo, hostname, sender,
                                            result, recipient, tokenSet, "HOLD"
                                    );
                                    return "HOLD " + (url == null ? ticket : url + ticket) + "\n";
                                } else {
                                    String url = Core.getURL(user);
                                    String ticket = SPF.getTicket(
                                            client, user, ip, helo, hostname, sender,
                                            result, recipient, tokenSet, "FLAG"
                                    );
                                    return "FLAG " + (url == null ? ticket : url + ticket) + "\n";
                                }
                            } else if (Provider.containsHELO(ip, hostname)) {
                                // Calcula frequencia de consultas.
                                String url = Core.getURL(user);
                                String ticket = SPF.addQueryHam(
                                        client, user, ip, helo, hostname, sender,
                                        result, recipient, tokenSet, "ACCEPT"
                                );
                                return result + " " + (url == null ? ticket : url + URLEncoder.encode(ticket, "UTF-8")) + "\n";
                            } else if (SPF.hasYellow(tokenSet)) {
                                Analise.processToday(ip);
                                Analise.processToday(mx);
                                boolean defer = Defer.defer(fluxo, Core.getDeferTimeYELLOW());
                                Action action = client == null ? Action.DEFER : client.getActionYELLOW();
                                if (defer && action == Action.DEFER) {
                                    // Pelo menos um identificador do conjunto está em greylisting com atrazo de 10min.
                                    SPF.addQuery(
                                            client, user, ip, helo, hostname, sender,
                                            result, recipient, tokenSet, "GREYLIST"
                                    );
                                    return "GREYLIST\n";
                                } else if (defer && action == Action.HOLD) {
                                    String url = Core.getURL(user);
                                    String ticket = SPF.getTicket(
                                            client, user, ip, helo, hostname, sender,
                                            result, recipient, tokenSet, "HOLD"
                                    );
                                    return "HOLD " + (url == null ? ticket : url + ticket) + "\n";
                                } else {
                                    String url = Core.getURL(user);
                                    String ticket = SPF.getTicket(
                                            client, user, ip, helo, hostname, sender,
                                            result, recipient, tokenSet, "FLAG"
                                    );
                                    return "FLAG " + (url == null ? ticket : url + ticket) + "\n";
                                }
                            } else if (SPF.isFlood(tokenSet) && Defer.defer(origem, Core.getDeferTimeFLOOD())) {
                                Analise.processToday(ip);
                                Analise.processToday(mx);
                                // Pelo menos um identificador está com frequência superior ao permitido.
                                Server.logDebug("FLOOD " + tokenSet);
                                SPF.addQuery(
                                        client, user, ip, helo, hostname, sender,
                                        result, recipient, tokenSet, "GREYLIST"
                                );
                                return "GREYLIST\n";
                            } else if (result.equals("SOFTFAIL") && Defer.defer(fluxo, Core.getDeferTimeSOFTFAIL())) {
                                Analise.processToday(ip);
                                Analise.processToday(mx);
                                // SOFTFAIL com atrazo de 1min.
                                SPF.addQuery(
                                        client, user, ip, helo, hostname, sender,
                                        result, recipient, tokenSet, "GREYLIST"
                                );
                                return "GREYLIST\n";
                            } else {
                                Analise.processToday(ip);
                                Analise.processToday(mx);
                                // Calcula frequencia de consultas.
                                String url = Core.getURL(user);
                                String ticket = SPF.addQueryHam(
                                        client, user, ip, helo, hostname, sender,
                                        result, recipient, tokenSet, "ACCEPT"
                                );
                                return result + " " + (url == null ? ticket : url + URLEncoder.encode(ticket, "UTF-8")) + "\n";
                            }
                        }
                    } catch (ProcessException ex) {
                        if (ex.isErrorMessage("HOST NOT FOUND")) {
                            return "NXDOMAIN\n";
                        } else {
                            throw ex;
                        }
                    }
                } else {
                    return "INVALID QUERY\n";
                }
            }
            return result;
        } catch (ProcessException ex) {
            Server.logError(ex);
            return ex.getMessage() + "\n";
        } catch (Exception ex) {
            Server.logError(ex);
            return "ERROR: FATAL\n";
        }
    }
    
    private static boolean enviarLiberacao(
            String url,
            String remetente,
            String destinatario
            ) {
        if (
                Core.hasOutputSMTP()
                && Core.hasAdminEmail()
                && Domain.isValidEmail(remetente)
                && Domain.isValidEmail(destinatario)
                && url != null
                && !NoReply.contains(remetente, true)
                ) {
            try {
                Server.logDebug("sending liberation by e-mail.");
                Locale locale = Core.getDefaultLocale(remetente);
                InternetAddress[] recipients = InternetAddress.parse(remetente);
                MimeMessage message = Core.newMessage();
                message.addRecipients(Message.RecipientType.TO, recipients);
                String subject;
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                   subject = "Liberação de recebimento";
                } else {
                    subject = "Receiving release";
                }
                message.setSubject(subject);
                // Corpo da mensagem.
                StringBuilder builder = new StringBuilder();
                builder.append("<!DOCTYPE html>\n");
                builder.append("<html lang=\"");
                builder.append(locale.getLanguage());
                builder.append("\">\n");
                builder.append("  <head>\n");
                builder.append("    <meta charset=\"UTF-8\">\n");
                builder.append("    <title>");
                builder.append(subject);
                builder.append("</title>\n");
                ServerHTTP.loadStyleCSS(builder);
                builder.append("  </head>\n");
                builder.append("  <body>\n");
                builder.append("    <div id=\"container\">\n");
                builder.append("      <div id=\"divlogo\">\n");
                builder.append("        <img src=\"cid:logo\">\n");
                builder.append("      </div>\n");
                ServerHTTP.buildMessage(builder, subject);
                if (locale.getLanguage().toLowerCase().equals("pt")) {
                    ServerHTTP.buildText(builder, "O recebimento da sua mensagem para " + destinatario + " está sendo atrasado por suspeita de SPAM.");
                    ServerHTTP.buildText(builder, "Para que sua mensagem seja liberada, acesse este link e resolva o desafio reCAPTCHA:");
                } else {
                    ServerHTTP.buildText(builder, "Receiving your message to " + destinatario + " is being delayed due to suspected SPAM.");
                    ServerHTTP.buildText(builder, "In order for your message to be released, access this link and resolve the reCAPTCHA:");
                }
                ServerHTTP.buildText(builder, "<a href=\"" + url + "\">" + url + "</a>");
                ServerHTTP.buildFooter(builder, locale, Core.getListUnsubscribeURL(locale, recipients[0]));
                builder.append("    </div>\n");
                builder.append("  </body>\n");
                builder.append("</html>\n");
                // Making HTML part.
                MimeBodyPart htmlPart = new MimeBodyPart();
                htmlPart.setContent(builder.toString(), "text/html;charset=UTF-8");
                // Making logo part.
                MimeBodyPart logoPart = new MimeBodyPart();
                File logoFile = ServerHTTP.getWebFile("logo.png");
                logoPart.attachFile(logoFile);
                logoPart.setContentID("<logo>");
                logoPart.addHeader("Content-Type", "image/png");
                logoPart.setDisposition(MimeBodyPart.INLINE);
                // Join both parts.
                MimeMultipart content = new MimeMultipart("related");
                content.addBodyPart(htmlPart);
                content.addBodyPart(logoPart);
                // Set multiplart content.
                message.setContent(content);
                message.saveChanges();
                // Enviar mensagem.
                return Core.sendMessage(locale, message, 30000);
            } catch (NameNotFoundException ex) {
                return false;
            } catch (MailConnectException ex) {
                return false;
            } catch (SendFailedException ex) {
                return false;
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
            }
        } else {
            return false;
        }
    }
    
    public static String createTicket(long time, TreeSet<String> tokenSet) throws ProcessException {
        String ticket = "spam";
        for (String token : tokenSet) {
            ticket += " " + token;
        }
        byte[] byteArray = Core.encodeHuffmanPlus(ticket, 8);
        byteArray[0] = (byte) (time & 0xFF);
        byteArray[1] = (byte) ((time = time >>> 8) & 0xFF);
        byteArray[2] = (byte) ((time = time >>> 8) & 0xFF);
        byteArray[3] = (byte) ((time = time >>> 8) & 0xFF);
        byteArray[4] = (byte) ((time = time >>> 8) & 0xFF);
        byteArray[5] = (byte) ((time = time >>> 8) & 0xFF);
        byteArray[6] = (byte) ((time = time >>> 8) & 0xFF);
        byteArray[7] = (byte) ((time >>> 8) & 0xFF);
        return Server.encryptURLSafe(byteArray);
    }

    private static Date getTicketDate(String date) throws ProcessException {
        try {
            return Server.parseTicketDate(date);
        } catch (ParseException ex) {
            throw new ProcessException("ERROR: INVALID TICKET", ex);
        }
    }
    
    public static TreeSet<String> expandTokenSet(
            TreeSet<String> tokenSet) {
        TreeSet<String> expandedSet = new TreeSet<>();
        for (String token : tokenSet) {
            if (token != null) {
                expandedSet.add(token);
                boolean expandDomain;
                if (token.startsWith("@") && Domain.isHostname(token.substring(1))) {
                    token = '.' + token.substring(1);
                    expandDomain = true;
                } else if (!token.startsWith("@") && Domain.isMailFrom(token)) {
                    expandDomain = false;
                } else if (token.startsWith(".") && Domain.isHostname(token.substring(1))) {
                    expandDomain = true;
                } else if (!token.startsWith(".") && Domain.isHostname(token)) {
                    token = '.' + token;
                    expandDomain = true;
                } else {
                    expandDomain = false;
                }
                if (expandDomain) {
                    try {
                        String dominio = Domain.extractDomain(token, true);
                        expandedSet.add(dominio);
                    } catch (ProcessException ex) {
                        if (!ex.isErrorMessage("RESERVED")) {
                            Server.logError(ex);
                        }
                    }
                }
            }
        }
        return expandedSet;
    }
    
    public static String getTicket(
            Client client,
            User user,
            String ip,
            String helo,
            String hostname,
            String sender,
            String qualifier,
            String recipient,
            TreeSet<String> tokenSet,
            String result
            ) throws ProcessException {
        long time;
        if (user == null) {
            time = Server.getNewUniqueTime();
        } else {
            Object[] resultSet = user.getDeferedQuery(
                    ip, hostname, sender, recipient, result
            );
            if (resultSet == null) {
                user.addQuery(
                        time = Server.getNewUniqueTime(),
                        client, ip, helo, hostname,
                        sender, qualifier, recipient, tokenSet, result
                );
            } else {
                time = (Long) resultSet[0];
            }
        }
        return SPF.createTicket(time, tokenSet);
    }
    
    public static String getTicket(
            TreeSet<String> tokenSet
            ) throws ProcessException {
        long time = Server.getNewUniqueTime();
        return SPF.createTicket(time, tokenSet);
    }    
                    
    public static String addQueryHam(
            Client client,
            User user,
            String ip,
            String helo,
            String hostname,
            String sender,
            String qualifier,
            String recipient,
            TreeSet<String> tokenSet,
            String result
            ) throws ProcessException {
        long time;
        if (user == null) {
            time = Server.getNewUniqueTime();
        } else {
            Object[] resultSet = user.getDeferedQuery(
                    ip, hostname, sender, recipient, result
            );
            if (resultSet == null) {
                user.addQuery(
                        time = Server.getNewUniqueTime(),
                        client, ip, helo, hostname, sender,
                        qualifier, recipient, tokenSet, result
                );
            } else {
                time = (Long) resultSet[0];
            }
        }
        for (String token : expandTokenSet(tokenSet)) {
            if (isValidReputation(token)) {
                Distribution distribution = CacheDistribution.get(token, true);
                distribution.addQueryHam(time);
                distribution.getStatus(token);
            }
        }
        return SPF.createTicket(time, tokenSet);
    }
    
    public static boolean setHam(long time, TreeSet<String> tokenSet) {
        boolean modified = false;
        for (String token : expandTokenSet(tokenSet)) {
            if (isValidReputation(token)) {
                Distribution distribution = CacheDistribution.get(token, true);
                modified |= distribution.addHam(time);
                distribution.getStatus(token);
            }
        }
        return modified;
    }
    
    public static boolean setSpam(long time, TreeSet<String> tokenSet) {
        boolean modified = false;
        for (String token : expandTokenSet(tokenSet)) {
            if (isValidReputation(token)) {
                Distribution distribution = CacheDistribution.get(token, true);
                modified |= distribution.addSpam(time);
                distribution.getStatus(token);
            }
        }
        return modified;
    }
    
    public static Object[] addQuerySpam(
            Client client,
            User user,
            String ip,
            String helo,
            String hostname,
            String sender,
            String qualifier,
            String recipient,
            TreeSet<String> tokenSet,
            String result
            ) throws ProcessException {
        long time;
        Object[] resultSet;
        if (user == null) {
            time = Server.getNewUniqueTime();
            resultSet = null;
        } else {
            resultSet = user.getDeferedQuery(
                    ip, hostname, sender, recipient, result
            );
            if (resultSet == null) {
                time = Server.getNewUniqueTime();
                resultSet = new Object[2];
                resultSet[0] = time;
                resultSet[1] = user.addQuery(
                        time, client, ip, helo, hostname, sender,
                        qualifier, recipient, tokenSet, result
                );
            } else {
                time = (Long) resultSet[0];
            }
        }
        for (String token : expandTokenSet(tokenSet)) {
            if (isValidReputation(token)) {
                Distribution distribution = CacheDistribution.get(token, true);
                if (Ignore.contains(token)) {
                    distribution.addQueryHam(time);
                    distribution.getStatus(token);
                } else {
                    distribution.addQuerySpam(time);
                    distribution.getStatus(token);
                    Peer.sendToAll(token, distribution);
                }
            }
        }
        return resultSet;
    }
    
    public static void addQuery(
            Client client,
            User user,
            String ip,
            String helo,
            String hostname,
            String sender,
            String qualifier,
            String recipient,
            TreeSet<String> tokenSet,
            String result
            ) throws ProcessException {
        if (user != null) {
            Object[] resultSet = user.getDeferedQuery(
                    ip, hostname, sender, recipient, result
            );
            if (resultSet == null) {
                user.addQuery(
                        Server.getNewUniqueTime(),
                        client, ip, helo, hostname, sender,
                        qualifier, recipient, tokenSet, result
                );
            }
        }
    }
    
    public static void createDistribution(String token) {
        Distribution distribution = CacheDistribution.get(token, true);
        distribution.getStatus(token);
    }
    
    public static Status getStatus(String token, boolean refresh) {
        Distribution distribution = CacheDistribution.get(token, false);
        if (distribution == null) {
            return Status.GREEN;
        } else if (refresh) {
            return distribution.getStatus(token);
        } else {
            return distribution.getStatus();
        }
    }
    
    public static boolean isGood(String token) {
        Distribution distribution = CacheDistribution.get(token, false);
        if (distribution == null) {
            return false;
        } else {
            return distribution.isGood();
        }
    }
    
    public static Status getStatus(String token) {
        if (isValidReputation(token)) {
            Distribution distribution = CacheDistribution.get(token, false);
            if (distribution == null) {
                return Status.GREEN;
            } else {
                return distribution.getStatus(token);
            }
        } else {
            return Status.GREEN;
        }
    }

    public static boolean isRed(String token) {
        if (isValidReputation(token)) {
            Distribution distribution = CacheDistribution.get(token, false);
            if (distribution == null) {
                return false;
            } else {
                return distribution.isRed(token);
            }
        } else {
            return false;
        }
    }

    public static boolean isYellow(String token) {
        if (isValidReputation(token)) {
            Distribution distribution = CacheDistribution.get(token, false);
            if (distribution == null) {
                // Distribuição não encontrada.
                // Considerar que não está listado.
                return false;
            } else {
                return distribution.isYellow(token);
            }
        } else {
            return false;
        }
    }
    
    public static boolean isGreen(String token) {
        if (isValidReputation(token)) {
            Distribution distribution = CacheDistribution.get(token, false);
            if (distribution == null) {
                // Distribuição não encontrada.
                // Considerar que não está listado.
                return true;
            } else {
                return distribution.isGreen(token);
            }
        } else {
            return false;
        }
    }
    
    public static boolean isNotGreen(String token) {
        if (isValidReputation(token)) {
            Distribution distribution = CacheDistribution.get(token, false);
            if (distribution == null) {
                // Distribuição não encontrada.
                // Considerar que não está listado.
                return false;
            } else {
                return distribution.isNotGreen(token);
            }
        } else {
            return false;
        }
    }
    
    public static boolean isGreen(String token, boolean refresh) {
        if (isValidReputation(token)) {
            Distribution distribution = CacheDistribution.get(token, false);
            if (distribution == null) {
                return true;
            } else if (refresh) {
                return distribution.isGreen(token);
            } else {
                return distribution.isGreen();
            }
        } else {
            return false;
        }
    }
    
    public static boolean isFlood(String token) {
        if (Ignore.contains(token)) {
            return false;
        } else if (isValidReputation(token)) {
            Distribution distribution = CacheDistribution.get(token, false);
            if (distribution == null) {
                // Distribuição não encontrada.
                // Considerar que não é rajada.
                return false;
            } else {
                return distribution.isFlood(token);
            }
        } else {
            return false;
        }
    }
    
    public static boolean isGreen(TreeSet<String> tokenSet) {
        for (String token : expandTokenSet(tokenSet)) {
            if (isNotGreen(token)) {
                return false;
            }
        }
        return true;
    }

    public static boolean hasYellow(TreeSet<String> tokenSet) {
        for (String token : expandTokenSet(tokenSet)) {
            if (isYellow(token)) {
                return true;
            }
        }
        return false;
    }

    public static boolean hasRed(TreeSet<String> tokenSet) {
        for (String token : expandTokenSet(tokenSet)) {
            if (isRed(token)) {
                return true;
            }
        }
        return false;
    }
    
    private static boolean isFlood(
            TreeSet<String> tokenSet
            ) throws ProcessException {
        for (String token : expandTokenSet(tokenSet)) {
            if (isFlood(token) && !Ignore.contains(token)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Enumeração do status da distribuição.
     */
    public enum Status implements Serializable {

        GRAY, // Obsoleto
        BLACK, // Obsoleto
        
        WHITE, // Whitelisted
        GREEN,
        YELLOW,
        RED,
        BLOCK; // Blocked.
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
        
        private long lastQuery; // Última consulta à distribuição.
        private Status status; // Status atual da distribuição.
        private NormalDistribution frequency = null; // Frequência média em segundos.
        
        private TreeSet<Long> hamSet = new TreeSet<>();
        private TreeSet<Long> spamSet = new TreeSet<>();
        private boolean ready = false;
        private boolean good = false;
        
        public Distribution() {
            lastQuery = 0;
            status = Status.GREEN;
            CacheDistribution.CHANGED = true;
        }
        
        public synchronized void reset() {
            hamSet.clear();
            spamSet.clear();
            lastQuery = 0;
            status = Status.GREEN;
            frequency = null;
            CacheDistribution.CHANGED = true;
        }
        
        public synchronized Distribution replicate() {
            Distribution clone = new Distribution();
            clone.lastQuery = this.lastQuery;
            clone.status = this.status;
            clone.frequency = this.frequency == null ? null : this.frequency.replicate();
            clone.hamSet.addAll(this.hamSet);
            clone.spamSet.addAll(this.spamSet);
            clone.ready = this.ready;
            return clone;
        }

        public boolean isExpired7() {
            return System.currentTimeMillis() - lastQuery > 604800000;
        }

        public boolean isExpired14() {
            return System.currentTimeMillis() - lastQuery > 604800000 * 2;
        }
        
        public synchronized boolean dropExpiredQuery() {
            long time = System.currentTimeMillis() - 604800000;
            TreeSet<Long> removeSet = new TreeSet<>();
            removeSet.addAll(hamSet.headSet(time));
            removeSet.addAll(spamSet.headSet(time));
            boolean hamChanged = hamSet.removeAll(removeSet);
            boolean spamChanged = spamSet.removeAll(removeSet);
            ready |= hamChanged;
            hairCut();
            return hamChanged || spamChanged;
        }
        
        public int getTotalSize() {
            return hamSet.size() + spamSet.size();
        }

        public synchronized boolean clear() {
            hamSet.addAll(spamSet);
            spamSet.clear();
            status = Status.GREEN;
            CacheDistribution.CHANGED = true;
            return true;
        }

        public boolean hasFrequency() {
            return frequency != null;
        }
        
        public Double getFrequencyMin() {
            if (frequency == null) {
                return null;
            } else {
                return frequency.getMinimum();
            }
        }

        public boolean hasLastQuery() {
            return lastQuery > 0;
        }
        
        public long getIdleTimeMillis() {
            if (lastQuery == 0) {
                return 0;
            } else {
                return System.currentTimeMillis() - lastQuery;
            }
        }
        
        public Float[] getFrequencyXiSum() {
            if (frequency == null) {
                return null;
            } else {
                int frequencyInt = frequency.getMaximumInt();
                long idleTimeInt = getIdleTimeMillis();
                if (idleTimeInt > frequencyInt * 5 && idleTimeInt > 3600000) {
                    return null;
                } else {
                    return frequency.getXiSum();
                }
            }
        }

        public String getFrequencyLiteral() {
            if (hasFrequency()) {
                int frequencyInt = frequency.getMaximumInt();
                long idleTimeInt = getIdleTimeMillis();
                if (idleTimeInt > frequencyInt * 5 && idleTimeInt > 3600000) {
                    return "DEAD";
                } else {
                    char sinal = '~';
                    if (idleTimeInt > frequencyInt * 3) {
                        sinal = '>';
                    }
                    if (frequencyInt >= 3600000) {
                        return sinal + ((frequencyInt / 3600000) + "h");
                    } else if (frequencyInt >= 60000) {
                        return sinal + ((frequencyInt / 60000) + "min");
                    } else if (frequencyInt >= 1000) {
                        return sinal + ((frequencyInt / 1000) + "s");
                    } else {
                        return sinal + (frequencyInt + "ms");
                    }
                }
            } else {
                return "UNDEFINED";
            }
        }

        private float getInterval(long currentTime, boolean refresh) {
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

        public void addQueryHam(long time) {
            addHam(time);
            float interval = getInterval(time, true);
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
        
        public void addQuerySpam(long time) {
            addSpam(time);
            float interval = getInterval(time, true);
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
        
        public synchronized int getHAM() {
            return hamSet.size();
        }
        
        public synchronized int getSPAM() {
            return spamSet.size();
        }
        
        public synchronized float getSpamProbability() {
            int ham = hamSet.size();
            int spam = spamSet.size();
            if (ham + spam == 0) {
                return 0.0f;
            } else {
                return (float) spam / (float) (ham + spam);
            }
        }
        
        public float getSpamProbability(String token) {
            int[] binomial = getBinomial();
            if (token != null) {
                for (Peer peer : Peer.getSet()) {
                    short reputationMax = peer.getReputationMax();
                    if (reputationMax > 0) {
                        Peer.Binomial peerBinomial = peer.getReputation(token);
                        if (peerBinomial != null) {
                            int hamInt = peerBinomial.getHAM();
                            int spamInt = peerBinomial.getSPAM();
                            int total = hamInt + spamInt;
                            if (total > reputationMax) {
                                float proporcion = (float) reputationMax / total;
                                hamInt = (int) (hamInt * proporcion);
                                spamInt = (int) (spamInt * proporcion);
                            }
                            binomial[0] += hamInt;
                            binomial[1] += spamInt;
                        }
                    }
                }
            }
            int total = binomial[0] + binomial[1];
            float probability = (float) binomial[1] / (float) total;
            good = binomial[0] > 512 && binomial[1] < 32;
            if (total == 0) {
                return 0.0f;
            } else if (probability > LIMIAR1 && binomial[1] < 16) {
                return LIMIAR1;
            } else if (probability > LIMIAR2 && binomial[1] < 32) {
                return LIMIAR2;
            } else if (probability > LIMIAR3 && binomial[1] < 64) {
                return LIMIAR3;
            } else {
                return probability;
            }
        }
        
        public Status getStatus() {
            return status;
        }
        
        /**
         * Máquina de estados para listar em um pico e retirar a listagem
         * somente quando o total cair consideravelmente após este pico.
         *
         * @return o status atual da distribuição.
         */
        public Status getStatus(String token) {
            Status statusOld = status;
            float probability = getSpamProbability(token);
            if (probability < LIMIAR1) {
                status = Status.GREEN;
            } else if (probability > LIMIAR2) {
                status = Status.RED;
            } else if (statusOld == Status.RED) {
                status = Status.RED;
            } else {
                status = Status.YELLOW;
            }
            return status;
        }
        
        public boolean isGood() {
            return good;
        }
        
        public boolean isGreen() {
            return status == Status.GREEN;
        }
        
        public boolean isRed() {
            return status == Status.RED;
        }

        public boolean isRed(String token) {
            return getStatus(token) == Status.RED;
        }
        
        public boolean isGreen(String token) {
            return getStatus(token) == Status.GREEN;
        }
        
        public boolean isNotGreen(String token) {
            return getStatus(token) != Status.GREEN;
        }

        public boolean isYellow(String token) {
            return getStatus(token) == Status.YELLOW;
        }
        
        public boolean isFlood(String token) {
            Double frequencyLocal = getFrequencyMin();
            if (frequencyLocal == null) {
                return false;
            } else if (Subnet.isValidIP(token)) {
                return frequencyLocal < Core.getFloodTimeIP();
            } else if (Domain.isMailFrom(token)) {
                return frequencyLocal < Core.getFloodTimeSender();
            } else {
                return frequencyLocal < Core.getFloodTimeHELO();
            }
        }

        public synchronized boolean removeSpam(long time) {
            hamSet.add(time);
            spamSet.remove(time);
            CacheDistribution.CHANGED = true;
            return true;
        }
        
        public void hairCut() {
            while (getTotalSize() > Core.getReputationLimit()) {
                long firstHam = hamSet.isEmpty() ? Long.MAX_VALUE : hamSet.first();
                long firstSpam = spamSet.isEmpty() ? Long.MAX_VALUE : spamSet.first();
                long time = Math.min(firstHam, firstSpam);
                boolean hamChanged = hamSet.remove(time);
                boolean spamChanged = spamSet.remove(time);
                CacheDistribution.CHANGED |= hamChanged || spamChanged;
            }
        }

        public synchronized boolean addSpam(long time) {
            boolean hamChanged = hamSet.remove(time);
            boolean spamChanged = spamSet.add(time);
            boolean changed = hamChanged || spamChanged;
            CacheDistribution.CHANGED |= changed;
            hairCut();
            return changed;
        }
        
        public boolean isSpam(long time) {
            return spamSet.contains(time);
        }
        
        public synchronized boolean addHam(long time) {
            boolean hamChanged = hamSet.add(time);
            boolean spamChanged = spamSet.remove(time);
            boolean changed = hamChanged || spamChanged;
            CacheDistribution.CHANGED |= changed;
            hairCut();
            return changed;
        }
        
        public int[] getBinomial() {
            if (frequency == null) {
                return new int[2];
            } else if (ready) {
                int[] result = new int[2];
                result[0] = hamSet.size();
                result[1] = spamSet.size();
                return result;
            } else if (frequency.getMinimum() > 0.0d) {
                int complain = spamSet.size();
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
        
        public int[] getBinomial(String token) {
            int[] result = new int[2];
            if (token != null) {
                for (Peer peer : Peer.getSet()) {
                    short reputationMax = peer.getReputationMax();
                    if (reputationMax > 0) {
                        Peer.Binomial peerBinomial = peer.getReputation(token);
                        if (peerBinomial != null) {
                            int hamInt = peerBinomial.getHAM();
                            int spamInt = peerBinomial.getSPAM();
                            int total = hamInt + spamInt;
                            if (total > reputationMax) {
                                float proporcion = (float) reputationMax / total;
                                hamInt = (int) (hamInt * proporcion);
                                spamInt = (int) (spamInt * proporcion);
                            }
                            result[0] += hamInt;
                            result[1] += spamInt;
                        }
                    }
                }
            }
            if (ready) {
                result[0] += hamSet.size();
                result[1] += spamSet.size();
                return result;
            } else if (frequency != null && frequency.getMinimum() > 0.0d) {
                int complain = spamSet.size();
                double semana = 60 * 60 * 24 * 7;
                int total = (int) (semana / frequency.getMinimum());
                if (total < complain) {
                    total = complain;
                }
                int ham = total - complain;
                int spam = complain;
                result[0] += ham;
                result[1] += spam;
            }
            return result;
        }

        @Override
        public String toString() {
            return Float.toString(getSpamProbability(null));
        }
    }
    
    /**
     * Classe que representa a distribuição binomial entre HAM e SPAM.
     */
    public static final class Binomial implements Serializable {

        private static final long serialVersionUID = 1L;
        
        private int ham; // Quantidade total de HAM em sete dias.
        private int spam; // Quantidade total de SPAM em sete dias
        private final Status status;
        private NormalDistribution frequency = null;
        private long lastQuery = 0;
        
        public Binomial(String token, Distribution distribution) {
            int[] binomial = distribution.getBinomial(token);
            this.ham = binomial[0];
            this.spam = binomial[1];
            this.status = distribution.getStatus(token);
            this.frequency = distribution.frequency;
            this.lastQuery = distribution.lastQuery;
       }
        
        public Binomial(Status status) {
            this.status = status;
            this.ham = 0;
            this.spam = 0;
            this.frequency = null;
            this.lastQuery = 0;
        }
        
        public void add(String token, Distribution distribution) {
            int[] binomial = distribution.getBinomial(token);
            this.ham += binomial[0];
            this.spam += binomial[1];
            if (this.frequency == null) {
                this.frequency = distribution.frequency;
            } else {
                this.frequency.add(distribution.frequency);
            }
            if (this.lastQuery < distribution.lastQuery) {
                this.lastQuery = distribution.lastQuery;
            }
        }
        
        public int getSPAM() {
            return spam;
        }
        
        public int getHAM() {
            return ham;
        }
        
        public Status getStatus() {
            return status;
        }
        
        public boolean clear() {
            if (spam > 0) {
                this.ham += spam;
                this.spam = 0;
                return true;
            } else {
                return false;
            }
        }
        
        public float getSpamProbability() {
            int total = ham + spam;
            float probability = (float) spam / (float) total;
            if (total == 0) {
                return 0.0f;
            } else if (probability > LIMIAR1 && spam < 16) {
                return LIMIAR1;
            } else if (probability > LIMIAR2 && spam < 32) {
                return LIMIAR2;
            } else if (probability > LIMIAR3 && spam < 64) {
                return LIMIAR3;
            } else {
                return probability;
            }
        }
        
        public long getIdleTimeMillis() {
            if (lastQuery == 0) {
                return 0;
            } else {
                return System.currentTimeMillis() - lastQuery;
            }
        }
        
        public String getFrequencyLiteral() {
            if (frequency == null) {
                return "UNDEFINED";
            } else {
                int frequencyInt = frequency.getMaximumInt();
                long idleTimeInt = getIdleTimeMillis();
                if (idleTimeInt > frequencyInt * 5 && idleTimeInt > 604800000) {
                    return "DEAD";
                } else {
                    char sinal = '~';
                    if (idleTimeInt > frequencyInt * 3) {
                        sinal = '>';
                    }
                    if (frequencyInt >= 3600000) {
                        return sinal + ((frequencyInt / 3600000) + "h");
                    } else if (frequencyInt >= 60000) {
                        return sinal + ((frequencyInt / 60000) + "min");
                    } else if (frequencyInt >= 1000) {
                        return sinal + ((frequencyInt / 1000) + "s");
                    } else {
                        return sinal + (frequencyInt + "ms");
                    }
                }
            }
        }
        
        @Override
        public String toString() {
            return Float.toString(getSpamProbability());
        }
    }
}
