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
import java.io.BufferedReader;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Owner;
import net.spfbl.whois.Subnet;
import net.spfbl.whois.SubnetIPv4;
import net.spfbl.whois.SubnetIPv6;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Serializable;
import java.io.Writer;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.NavigableMap;
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
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
import net.spfbl.core.Client;
import net.spfbl.core.Core;
import net.spfbl.data.Block;
import net.spfbl.core.Defer;
import net.spfbl.core.Filterable.Filter;
import net.spfbl.core.NormalDistribution;
import net.spfbl.data.Ignore;
import net.spfbl.data.NoReply;
import net.spfbl.core.Peer;
import net.spfbl.core.ProcessException;
import net.spfbl.core.Regex;
import static net.spfbl.core.Regex.isHostname;
import static net.spfbl.core.Regex.isValidCIDR;
import static net.spfbl.core.Regex.isValidEmail;
import static net.spfbl.core.Regex.isValidIP;
import static net.spfbl.core.Regex.isValidIPv4;
import static net.spfbl.core.Regex.isValidIPv6;
import net.spfbl.data.Provider;
import net.spfbl.core.Reverse;
import net.spfbl.core.Server;
import net.spfbl.core.User;
import net.spfbl.core.User.Query;
import net.spfbl.data.Abuse;
import net.spfbl.data.CIDR;
import net.spfbl.data.Dictionary;
import net.spfbl.data.Generic;
import net.spfbl.data.FQDN;
import net.spfbl.data.Recipient;
import net.spfbl.data.Reputation;
import net.spfbl.data.Reputation.Flag;
import static net.spfbl.data.Reputation.Flag.HARMFUL;
import static net.spfbl.data.Reputation.Flag.UNDESIRABLE;
import net.spfbl.data.Trap;
import net.spfbl.data.White;
import net.spfbl.service.ServerHTTP;
import net.spfbl.service.ServerSMTP;
import org.apache.commons.lang3.SerializationUtils;
import static net.spfbl.core.NormalDistribution.newNormalDistribution;
import static net.spfbl.core.Regex.isValidRecipient;

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
    private boolean temporary = false; // Se o resultado é temporário.
    private int queries = 0; // Contador de consultas.
    private int nxdomain = 0; // Contador de inexistência de domínio.
    private long created = System.currentTimeMillis();
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
    private LinkedList<String> getRegistrySPF(
            String hostname,
            boolean bgWhenUnavailable
    ) throws ProcessException {
        LinkedList<String> registryList = new LinkedList<>();
        try {
            try {
                Attributes attributes = Server.getAttributesDNS(hostname, "SPF");
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
            } catch (Exception ex) {
                Server.logError(ex);
            }
            if (registryList.isEmpty()) {
                try {
                    Attributes attributes = Server.getAttributesDNS(hostname, "TXT");
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
                } catch (InvalidAttributeIdentifierException ex) {
                    // Não encontrou registro TXT.
                }
            }
            if (registryList.isEmpty()) {
                // Como o domínio não tem registro SPF,
                // utilizar um registro SPF de chute do sistema.
                String guess = CacheGuess.get(hostname);
                registryList.add(guess);
            }
            this.temporary = false;
            return registryList;
        } catch (NameNotFoundException ex) {
            this.temporary = false;
            return null;
        } catch (NamingException ex) {
            this.temporary = true;
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
            this.temporary = true;
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
        for (String token : midleList) {
            registry += ' ' + token;
        }
        if (redirect != null) {
            registry += ' ' + redirect;
        } else if (all != null) {
            registry += ' ' + all;
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
    
    public boolean isInexistent() {
        return nxdomain > 0;
    }
    
    public boolean isInexistent(int time) {
        if (nxdomain == 0) {
            return false;
        } else {
            long expired = (System.currentTimeMillis() - lastRefresh) / Server.MINUTE_TIME;
            return expired > time;
        }
    }
    
    public boolean isTemporary() {
        return temporary;
    }
    
    /**
     * 
     * @param time minutes to expire temporary refresh.
     * @return is temporary result if expired.
     */
    private boolean isTemporary(int time) {
        if (temporary) {
            long expired = (System.currentTimeMillis() - lastRefresh) / Server.MINUTE_TIME;
            return expired > time;
        } else {
            return false;
        }
    }
    
    public boolean isDefinitelyInexistent() {
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
    
    private void refresh(
            boolean load,
            boolean bgWhenUnavailable
    ) throws ProcessException {
        this.lastRefresh = System.currentTimeMillis();
        long time = System.currentTimeMillis();
        LinkedList<String> registryList = getRegistrySPF(
                hostname, bgWhenUnavailable
        );
        if (registryList == null) {
            updateNXDOMAIN();
            Server.logLookupSPF(time, hostname, "NXDOMAIN");
        } else if (registryList.isEmpty()) {
            updateNONE();
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
            update(
                    mechanismListLocal, allLocal,
                    redirectLocal, explanationLocal, errorQuery
            );
            Server.logLookupSPF(time, hostname, result);
        }
    }
    
    private synchronized void updateNXDOMAIN() {
        this.mechanismList = null;
        this.all = null;
        this.redirect = null;
        this.explanation = null;
        this.error = false;
        CacheSPF.CHANGED = true;
        this.addInexistent();
        this.queries = 0;
        this.lastRefresh = System.currentTimeMillis();
    }
    
    private synchronized void updateNONE() {
        this.mechanismList = new ArrayList<>();
        this.all = null;
        this.redirect = null;
        this.explanation = null;
        this.error = false;
        CacheSPF.CHANGED = true;
        this.nxdomain = 0;
        this.queries = 0;
        this.lastRefresh = System.currentTimeMillis();
    }
    
    private synchronized void update(
            ArrayList<Mechanism> mechanismListLocal,
            Qualifier allLocal,
            String redirectLocal,
            String explanationLocal,
            boolean errorQuery
    ) {
        this.mechanismList = mechanismListLocal;
        this.all = allLocal;
        this.redirect = redirectLocal;
        this.explanation = explanationLocal;
        this.error = errorQuery;
        CacheSPF.CHANGED = true;
        this.nxdomain = 0;
        this.queries = 0;
        this.lastRefresh = System.currentTimeMillis();
    }
    
    private static final Regex MECANISM_ALL_PATTERN = new Regex("^"
            + "(\\+|-|~|\\?)?all"
            + "$"
    );

    /**
     * Verifica se o whois é um mecanismo all válido.
     *
     * @param token o whois a ser verificado.
     * @return verdadeiro se o whois é um mecanismo all válido.
     */
    private static boolean isMechanismAll(String token) {
        token = token.toLowerCase();
        return MECANISM_ALL_PATTERN.matches(token);
    }
    
    private static final Regex MECANISM_IPV4_PATTERN = new Regex("^"
            + "((\\+|-|~|\\?)?ipv?4?:)?"
            + "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}"
            + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
            + "(/[0-9]{1,2})?"
            + "$"
    );

    /**
     * Verifica se o whois é um mecanismo ip4 válido.
     *
     * @param token o whois a ser verificado.
     * @return verdadeiro se o whois é um mecanismo ip4 válido.
     */
    private static boolean isMechanismIPv4(String token) {
        token = token.toLowerCase();
        return MECANISM_IPV4_PATTERN.matches(token);
    }
    
    private static final Regex EXTRACT_IPV4_PATTERN = new Regex("(:|^)"
            + "((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}"
            + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
            + "(/[0-9]{1,2})?)"
            + "$"
    );

    /**
     * Extrai um CIDR de IPv4 válido.
     *
     * @param token o whois a ser verificado.
     * @return um CIDR de IPv4 válido.
     */
    private static String extractIPv4CIDR(String token) {
        Matcher matcher = EXTRACT_IPV4_PATTERN.createMatcher(token.toLowerCase());
        String group = matcher.find() ? matcher.group(2) : null;
        EXTRACT_IPV4_PATTERN.offerMatcher(matcher);
        return group;
    }
    
    private static final Regex MECANISM_IPV6_PATTERN = new Regex("^"
            + "((\\+|-|~|\\?)?ipv?6?:)?"
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
            + "$"
    );

    /**
     * Verifica se o whois é um mecanismo ip6 válido.
     *
     * @param token o whois a ser verificado.
     * @return verdadeiro se o whois é um mecanismo ip6 válido.
     */
    private static boolean isMechanismIPv6(String token) {
        return MECANISM_IPV6_PATTERN.matches(token);
    }
    
    private static final Regex EXTRACT_IPV6_PATTERN = new Regex("(:|^)"
            + "(((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|"
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
            + "(%.+)?(\\/[0-9]{1,3})?)$"
    );

    /**
     * Extrai um CIDR de IPv6 válido.
     *
     * @param token o whois a ser verificado.
     * @return um CIDR de IPv6 válido.
     */
    private static String extractIPv6CIDR(String token) {
        Matcher matcher = EXTRACT_IPV6_PATTERN.createMatcher(token);
        String group = matcher.find() ? matcher.group(2) : null;
        EXTRACT_IPV6_PATTERN.offerMatcher(matcher);
        return group;
    }

    private static String expand(
            String hostname,
            String ip, String sender, String helo
    ) {
        int index = sender.indexOf('@');
        String local = sender.substring(0, index);
        String domain = sender.substring(index + 1);
        if (ip.contains(":")) {
            hostname = hostname.replace("%{v}", "ip6");
        } else {
            hostname = hostname.replace("%{v}", "in-addr");
        }
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
    
    private static final Regex MECANISM_A_PATTERN = new Regex("^"
            + "(\\+|-|~|\\?)?a"
            + "(:(?=.{1,255}$)[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?"
            + "(?:\\.[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?)*\\.?)?"
            + "(/[0-9]{1,2})?(//[0-9]{1,3})?"
            + "$"
    );

    /**
     * Verifica se o whois é um mecanismo a válido.
     *
     * @param token o whois a ser verificado.
     * @return verdadeiro se o whois é um mecanismo a válido.
     */
    private static boolean isMechanismA(String token) {
        token = expand(token, "127.0.0.1", "sender@domain.tld", "host.domain.tld").toLowerCase();
        return MECANISM_A_PATTERN.matches(token);
    }
    
    private static final Regex MECANISM_MX_PATTERN = new Regex("^"
            + "(\\+|-|~|\\?)?mx"
            + "(:(?=.{1,255}$)[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?"
            + "(?:\\.[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?)*\\.?)?"
            + "(\\.|/[0-9]{1,2})?(//[0-9]{1,3})?"
            + "$"
    );

    /**
     * Verifica se o whois é um mecanismo mx válido.
     *
     * @param token o whois a ser verificado.
     * @return verdadeiro se o whois é um mecanismo mx válido.
     */
    private static boolean isMechanismMX(String token) {
        token = expand(token, "127.0.0.1", "sender@domain.tld", "host.domain.tld").toLowerCase();
        return MECANISM_MX_PATTERN.matches(token);
    }
    
    private static final Regex MECANISM_PTR_PATTERN = new Regex("^"
            + "(\\+|-|~|\\?)?ptr"
            + "(:(?=.{1,255}$)[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?"
            + "(?:\\.[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?)*\\.?)?"
            + "$"
    );

    /**
     * Verifica se o whois é um mecanismo ptr válido.
     *
     * @param token o whois a ser verificado.
     * @return verdadeiro se o whois é um mecanismo ptr válido.
     */
    private static boolean isMechanismPTR(String token) {
        token = expand(token, "127.0.0.1", "sender@domain.tld", "host.domain.tld").toLowerCase();
        return MECANISM_PTR_PATTERN.matches(token);
    }
    
    private static final Regex MECANISM_EXISTIS_PATTERN = new Regex("^"
            + "(\\+|-|~|\\?)?exists:"
            + "((?=.{1,255}$)[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?"
            + "(?:\\.[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?)*\\.?)"
            + "$"
    );

    /**
     * Verifica se o whois é um mecanismo existis válido.
     *
     * @param token o whois a ser verificado.
     * @return verdadeiro se o whois é um mecanismo existis válido.
     */
    private static boolean isMechanismExistis(String token) {
        token = expand(token, "127.0.0.1", "sender@domain.tld", "host.domain.tld").toLowerCase();
        return MECANISM_EXISTIS_PATTERN.matches(token);
    }
    
    private static final Regex MECANISM_INCLUDE_PATTERN = new Regex("^"
            + "(\\+|-|~|\\?)?include:"
            + "(\\.?(?=.{1,255}$)[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?"
            + "(?:\\.[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?)*\\.?)"
            + "$"
    );

    /**
     * Verifica se o whois é um mecanismo include válido.
     *
     * @param token o whois a ser verificado.
     * @return verdadeiro se o whois é um mecanismo include válido.
     */
    private static boolean isMechanismInclude(String token) {
        token = expand(token, "127.0.0.1", "sender@domain.tld", "host.domain.tld").toLowerCase();
        return MECANISM_INCLUDE_PATTERN.matches(token);
    }
    
    private static final Regex MECANISM_REDIRECT_PATTERN = new Regex("^"
            + "redirect="
            + "((?=.{1,255}$)[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?"
            + "(?:\\.[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?)*\\.?)"
            + "$"
    );

    /**
     * Verifica se o whois é um modificador redirect válido.
     *
     * @param token o whois a ser verificado.
     * @return verdadeiro se o whois é um modificador redirect válido.
     */
    private static boolean isModifierRedirect(String token) {
        token = expand(token, "127.0.0.1", "sender@domain.tld", "host.domain.tld").toLowerCase();
        return MECANISM_REDIRECT_PATTERN.matches(token);
    }
    
    private static final Regex MODIFIER_EXPLANATION_PATTERN = new Regex("^"
            + "exp="
            + "((?=.{1,255}$)[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?"
            + "(?:\\.[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?)*\\.?)"
            + "$"
    );

    /**
     * Verifica se o whois é um modificador explanation válido.
     *
     * @param token o whois a ser verificado.
     * @return verdadeiro se o whois é um modificador explanation válido.
     */
    private static boolean isModifierExplanation(String token) {
        token = expand(token, "127.0.0.1", "sender@domain.tld", "host.domain.tld").toLowerCase();
        return MODIFIER_EXPLANATION_PATTERN.matches(token);
    }
    
    public boolean isRecent() {
        return (System.currentTimeMillis() - created) < Server.WEEK_TIME;
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
    
    public String getResultSafe(
            String ip,
            String sender,
            String helo,
            LinkedList<String> logList
    ) {
        try {
            return getResult(ip, sender, helo, logList);
        } catch (ProcessException ex) {
            return "NONE";
        }
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
    
    public Qualifier getQualifier(
            String ip,
            String sender,
            String helo
    ) throws ProcessException {
        return getQualifier(
                System.currentTimeMillis(),
                ip, sender, helo, 0,
                new TreeSet<>(),
                null
        );
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
        } else if (System.currentTimeMillis() - time > 10000) {
            throw new ProcessException("TIMEOUT");
        } else {
            boolean includeError = false;
            hostVisitedSet.add(getHostname());
            for (Mechanism mechanism : mechanismList) {
                if (System.currentTimeMillis() - time > 10000) {
                    throw new ProcessException("TIMEOUT");
                } else if (mechanism instanceof MechanismInclude) {
                    try {
                        MechanismInclude include = (MechanismInclude) mechanism;
                        Qualifier qualifier = include.getQualifierSPF(
                                time, ip, sender, helo, deep + 1,
                                hostVisitedSet, logList
                        );
                        if (qualifier == Qualifier.PASS) {
                            // Only PASS for include mechanism.
                            return qualifier;
                        }
                    } catch (ProcessException ex) {
                        if (ex.isErrorMessage("EMPTY")) {
                            // Registro SPF vazio no include.
                            // Continuar a verificação dos demais 
                            // mecanismos antes de efetivar o erro.
                            includeError = true;
                            if (logList != null) {
                                logList.add(getHostname() + ":" + mechanism + " => EMPTY");
                            }
                        } else if (ex.isErrorMessage("HOST NOT FOUND")) {
                            // Não foi possível fazer o include.
                            // O hostname mencionado não existe.
                            // Continuar a verificação dos demais 
                            // mecanismos antes de efetivar o erro.
                            includeError = true;
                            if (logList != null) {
                                logList.add(getHostname() + ":" + mechanism + " => HOST NOT FOUND");
                            }
                        } else if (ex.isErrorMessage("TIMEOUT")) {
                            // Timeout before include process.
                            includeError = true;
                            if (logList != null) {
                                logList.add(getHostname() + ":" + mechanism + " => NOT PROCESSED");
                            }
                        } else {
                            throw ex;
                        }
                    }
                } else if (mechanism instanceof MechanismPTR) {
                    if (mechanism.match(time, ip, sender, helo)) {
                        // Mecanismo PTR só será processado
                        // no primeiro nível da árvore.
                        Qualifier qualifier = mechanism.getQualifier();
                        logMechanism(mechanism, qualifier, logList);
                        return qualifier;
                    } else {
                        logMechanism(mechanism, null, logList);
                    }
                } else if (mechanism.match(time, ip, sender, helo)) {
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
            } else if (error || includeError) {
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

        PASS("pass"),
        FAIL("fail"),
        SOFTFAIL("softfail"),
        NEUTRAL("neutral");
        
        private final String description;

        private Qualifier(String description) {
            this.description = description;
        }
        
        public static Qualifier get(String name) {
            try {
                return valueOf(name.toUpperCase());
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
        
        public String getResult() {
            switch (this) {
                case PASS:
                    return "pass";
                case FAIL:
                    return "fail";
                case SOFTFAIL:
                    return "softfail";
                case NEUTRAL:
                    return "neutral";
                default:
                    return "none";
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

        public abstract boolean match(
                long time,
                String ip,
                String sender, String helo
        ) throws ProcessException;

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
            // Associação dos atributos.
            this.address = addressLocal;
            this.mask = maskLocal;
            this.reserved = reservedLocal;
        }
        
        public boolean isReserved() {
            return reserved;
        }

        @Override
        public boolean match(long time, String ip, String sender, String helo) {
            if (isReserved()) {
                // Sempre que estiver apontando para
                // blocos reservados, ignorar o mecanismo.
                return false;
            } else if (isValidIPv4(ip)) {
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
        public boolean match(long time, String ip, String sender, String helo) {
            if (isValidIPv6(ip)) {
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
                TreeSet<String> resultSet = new TreeSet<>();
                try {
                    Attributes attributes = Server.getAttributesDNS(hostname, "A");
                    Attribute attributeA = attributes.get("A");
                    if (attributeA != null) {
                        NamingEnumeration enumeration = attributeA.getAll();
                        while (enumeration.hasMoreElements()) {
                            String hostAddress = (String) enumeration.next();
                            int indexSpace = hostAddress.indexOf(' ') + 1;
                            hostAddress = hostAddress.substring(indexSpace);
                            if (!isValidIPv4(hostAddress)) {
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
                    Attributes attributes = Server.getAttributesDNS(hostname, "AAAA");
                    Attribute attributeAAAA = attributes.get("AAAA");
                    if (attributeAAAA != null) {
                        NamingEnumeration enumeration = attributeAAAA.getAll();
                        while (enumeration.hasMoreElements()) {
                            String hostAddress = (String) enumeration.next();
                            int indexSpace = hostAddress.indexOf(' ') + 1;
                            hostAddress = hostAddress.substring(indexSpace);
                            if (isHostname(hostAddress)) {
                                try {
                                    hostAddress = Inet6Address.getByName(hostAddress).getHostAddress();
                                } catch (UnknownHostException ex) {
                                    // Registro AAAA não encontrado.
                                    hostAddress = null;
                                }
                            }
                            if (isValidIPv6(hostAddress)) {
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
                if (!expression.contains("%")) {
                    loaded = true;
                }
            }
        }
        
        private synchronized ArrayList<Mechanism> getMechanismList() {
            ArrayList<Mechanism> list = new ArrayList<>();
            list.addAll(mechanismList);
            return list;
        }

        @Override
        public boolean match(long time, String ip, String sender, String helo) throws ProcessException {
            loadList(ip, sender, helo);
            for (Mechanism mechanism : getMechanismList()) {
                if (System.currentTimeMillis() - time > 10000) {
                    throw new ProcessException("TIMEOUT");
                } else if (mechanism.match(time, ip, sender, helo)) {
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
                    Attributes attributesMX = Server.getAttributesDNS(hostname, "MX");
                    Attribute attributeMX = attributesMX.get("MX");
                    if (attributeMX == null) {
                        Attributes attributesA = Server.getAttributesDNS(hostname, "A");
                        Attribute attributeA = attributesA.get("A");
                        if (attributeA != null) {
                            for (int i = 0; i < attributeA.size(); i++) {
                                String host4Address = (String) attributeA.get(i);
                                if (isValidIPv4(host4Address)) {
                                    if (maskIPv4 != null) {
                                        host4Address += "/" + maskIPv4;
                                    }
                                    mechanismList.add(new MechanismIPv4(host4Address));
                                    resultSet.add(host4Address);
                                }
                            }
                        }
                        Attributes attributesAAAA = Server.getAttributesDNS(hostname, "AAAA");
                        Attribute attributeAAAA = attributesAAAA.get("AAAA");
                        if (attributeAAAA != null) {
                            for (int i = 0; i < attributeAAAA.size(); i++) {
                                String host6Address = (String) attributeAAAA.get(i);
                                if (isValidIPv6(host6Address)) {
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
                            if (isValidIPv4(hostAddress)) {
                                if (maskIPv4 != null) {
                                    hostAddress += "/" + maskIPv4;
                                }
                                mechanismList.add(new MechanismIPv4(hostAddress));
                                resultSet.add(hostAddress);
                            } else if (isValidIPv6(hostAddress)) {
                                if (maskIPv6 != null) {
                                    hostAddress += "/" + maskIPv6;
                                }
                                mechanismList.add(new MechanismIPv6(hostAddress));
                                resultSet.add(hostAddress);
                            } else {
                                try {
                                    Attributes attributesA = Server.getAttributesDNS(hostAddress, "A");
                                    Attribute attributeA = attributesA.get("A");
                                    if (attributeA != null) {
                                        for (int i = 0; i < attributeA.size(); i++) {
                                            String host4Address = (String) attributeA.get(i);
                                            if (isValidIPv4(host4Address)) {
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
                                    Attributes attributesAAAA = Server.getAttributesDNS(hostAddress, "AAAA");
                                    Attribute attributeAAAA = attributesAAAA.get("AAAA");
                                    if (attributeAAAA != null) {
                                        for (int i = 0; i < attributeAAAA.size(); i++) {
                                            String host6Address = (String) attributeAAAA.get(i);
                                            if (isValidIPv6(host6Address)) {
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
        
        private synchronized ArrayList<Mechanism> getMechanismList() {
            ArrayList<Mechanism> list = new ArrayList<>();
            list.addAll(mechanismList);
            return list;
        }

        @Override
        public boolean match(long time, String ip, String sender, String helo) throws ProcessException {
            loadList(ip, sender, helo);
            for (Mechanism mechanism : getMechanismList()) {
                if (System.currentTimeMillis() - time > 10000) {
                    throw new ProcessException("TIMEOUT");
                } else if (mechanism.match(time, ip, sender, helo)) {
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
                long time, String ip, String sender,
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
        public boolean match(long time, String ip, String sender, String helo) throws ProcessException {
            long begin = System.currentTimeMillis();
            String hostname = getHostname(ip, sender, helo);
            try {
                Server.getAttributesDNS(hostname, "A");
                Server.logMecanismA(begin, hostname, "EXISTS");
                return true;
            } catch (CommunicationException ex) {
                Server.logMecanismA(begin, hostname, "TIMEOUT");
                return false;
            } catch (ServiceUnavailableException ex) {
                Server.logMecanismA(begin, hostname, "SERVFAIL");
                return false;
            } catch (NameNotFoundException ex) {
                Server.logMecanismA(begin, hostname, "NOT FOUND");
                return false;
            } catch (InvalidAttributeIdentifierException ex) {
                Server.logMecanismA(begin, hostname, "NOT FOUND");
                return false;
            } catch (InvalidNameException ex) {
                Server.logMecanismA(begin, hostname, "INVALID");
                return false;
            } catch (NamingException ex) {
                Server.logMecanismA(begin, hostname, "ERROR " + ex.getClass() + " " + ex.getMessage());
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
            } else if (spf.isEmpty()) {
                throw new ProcessException("EMPTY");
            } else {
                return spf.getQualifier(
                        time,
                        ip, sender, helo, deep,
                        hostVisitedSet, logList
                );
            }

        }

        @Override
        public boolean match(long time, String ip, String sender, String helo) throws ProcessException {
            throw new ProcessException("ERROR: FATAL ERROR"); // Não pode fazer o match direto.
        }
    }
    
    public boolean isEmpty() {
        if (mechanismList == null) {
            return true;
        } else {
            return mechanismList.isEmpty();
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
                SPF spf = getExact(host);
                if (spf != null && spf.isRegistryExpired14()) {
                    dropExact(host);
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

        private static boolean refresh(
                String address,
                boolean load
        ) throws ProcessException {
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
        
        private static SPF getSafe(String address) {
            try {
                return get(address, false);
            } catch (ProcessException ex) {
                return null;
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
                } else if (refresh || spf.isInexistent(10) || spf.isTemporary(10) || spf.isRegistryExpired()) {
                    try {
                        // Atualiza o registro se ele for antigo demais.
                        spf.refresh(false, false);
                    } catch (ProcessException ex) {
                        if (ex.isErrorMessage("DNS UNAVAILABLE")) {
                            // Manter registro anterior quando houver erro de DNS.
                            Server.logInfo(address + ": SPF temporarily unavailable.");
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
            dropExpired();
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
    }
    
    public static SPF getSPF(String sender) {
        try {
            return CacheSPF.get(sender, false);
        } catch (ProcessException ex) {
            Server.logError(ex);
            return null;
        }
    }
    
    public static Qualifier getQualifier(String ip, String sender, String helo, boolean refresh) {
        try {
            SPF spf = CacheSPF.get(sender, refresh);
            if (spf == null) {
                return null;
            } else {
                return spf.getQualifier(
                        System.currentTimeMillis(),
                        ip, sender, helo, 0,
                        new TreeSet<>(), null
                );
            }
        } catch (ProcessException ex) {
            return null;
        }
    }
    
    public static Qualifier getQualifierIfExists(
            String ip, String sender, String helo
    ) {
        return getQualifierIfExists(ip, sender, helo, (Qualifier) null);
    }
    
    public static Qualifier getQualifierIfExists(
            String ip, String sender, String helo,
            Qualifier defaultQualifier
    ) {
        try {
            String host = Domain.extractHost(sender, false);
            if (host == null) {
                return defaultQualifier;
            } else {
                SPF spf = CacheSPF.getExact(host);
                if (spf == null) {
                    return defaultQualifier;
                } else {
                    return spf.getQualifier(
                            System.currentTimeMillis(),
                            ip, sender, helo, 0,
                            new TreeSet<>(), null
                    );
                }
            }
        } catch (ProcessException ex) {
            return defaultQualifier;
        }
    }
    
    public static boolean addComplainSafe(String token) {
        try {
            return addComplain(token);
        } catch (ProcessException ex) {
            return false;
        }
    }
    
    public static boolean addComplain(String token) throws ProcessException {
        if (token == null) {
            return false;
        } else if (isValidIP(token)) {
            token = Subnet.normalizeIP(token);
            if (Ignore.contains(token)) {
                return false;
            } else {
                Distribution distribution = CacheDistribution.get(token, true);
                distribution.addSpam(Server.getNewUniqueTime());
                Peer.sendToAll(token, distribution);
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
                    } else if (token.startsWith(">") && isValidEmail(token.substring(1))) {
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
                Server.log(time, Core.Level.DEBUG, "CMPLN", origin, date.getTime(), ticket, blackSet, recipient);
                return blackSet;
            }
        }
    }
    
    public static long getDateTicket(
            String ticket) throws ProcessException {
        byte[] byteArray = Server.decryptToByteArrayURLSafe(ticket);
        if (byteArray == null) {
            return 0;
        } else if (byteArray.length > 8) {
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
    }
    
    private static String getHoldStatus(
            Client client,
            long timeKey,
            User.Query query
    ) {
        if (query == null) {
            return "HOLD";
        } else if (query.isWhiteKey()) {
            query.clearBlock(timeKey);
            query.setResult("WHITE");
            query.addBeneficial(timeKey);
            return "WHITE";
        } else if (query.isBlockKey()) {
            SPF.setSpam(timeKey, query.getTokenSet());
            query.clearWhite(timeKey);
            query.setResult("BLOCK");
            Abuse.offer(timeKey, query);
            query.addUndesirable(timeKey);
            return "REMOVE";
        } else if (query.isBanned()) {
            query.blockKey(timeKey, "BANNED");
            query.setResultFilter("BLOCK", "ORIGIN_BANNED;" + query.getBannedKey());
            Abuse.offer(timeKey, query);
            query.addHarmful(timeKey);
            return "REMOVE";
        } else if (query.isWhiteKeyByAdmin()) {
            query.whiteKey(timeKey);
            query.setResultFilter("WHITE", "ORIGIN_WHITE_KEY_ADMIN");
            query.addBeneficial(timeKey);
            return "WHITE";
        } else if (query.isBlockKeyByAdmin()) {
            query.blockKey(timeKey, "ADMIN");
            query.setResultFilter("BLOCK", "ORIGIN_BLOCK_KEY_ADMIN;" + query.getBlockKey());
            Abuse.offer(timeKey, query);
            query.addUndesirable(timeKey);
            return "REMOVE";
        } else if (query.isResult("WHITE")) {
            query.addBeneficial(timeKey);
            return "WHITE";
        } else if (query.isResult("BLOCK")) {
            query.blockKey(timeKey, "BLOCK");
            Abuse.offer(timeKey, query);
            query.addUndesirable(timeKey);
            return "REMOVE";
        } else if (query.isResult("ACCEPT")) {
            query.addAcceptable();
            return "ACCEPT";
        } else if (query.isResult("GREYLIST")) {
            return "REMOVE";
        } else {
            return "HOLD";
        }
    }
    
    public static String getHoldStatus(
            Client client,
            String ticket,
            LinkedList<User> userList
    ) {
        if (ticket == null) {
            return "INVALID";
        } else {
            byte[] byteArray = Server.decryptToByteArrayURLSafe(ticket);
            if (byteArray == null) {
                return "ERROR";
            } else if (byteArray.length > 8) {
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
                        if (token.endsWith(":") && isValidEmail(token.substring(0,token.length()-1))) {
                            user = User.get(token.substring(0,token.length()-1));
                            break;
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
                                } else if (token.startsWith(">") && isValidEmail(token.substring(1))) {
                                    recipient = token.substring(1);
                                } else if (token.endsWith(":") && isValidEmail(token.substring(0,token.length()-1))) {
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
                            Server.log(time, Core.Level.DEBUG, "CMPLN", origin, date, ticket, blackSet, recipient);
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
            String origin, long timeKey,
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
                    distribution.addHam(timeKey);
                } else if (distribution.addSpam(timeKey)) {
                    distribution.getStatus(key);
                    Peer.sendToAll(key, distribution);
                }
                blackSet.add(key);
            }
            Server.log(time, Core.Level.DEBUG, "CMPLN", origin, timeKey, tokenSet.toString(), blackSet, recipient);
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
            Server.logQuery(time, "CLEAR", date.getTime(), origin, tokenSet);
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
                                } else if (token.startsWith(">") && isValidEmail(token.substring(1))) {
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
                            Server.logQuery(time, "CLEAR", date, origin, tokenSet);
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
        
        private static synchronized Distribution dropExact(String key) {
            return MAP.remove(key);
        }

        private static synchronized Distribution putExact(String key, Distribution value) {
            if (key == null) {
                return null;
            } else if (value == null) {
                return null;
            } else {
                return MAP.put(key, value);
            }
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
        
        private static Distribution getExact(String host) {
            if (host == null) {
                return null;
            } else {
                return MAP.get(host);
            }
        }
        
        private static synchronized NavigableMap<String,Distribution> getInclusiveSubMap(
                String fromKey, String toKey
        ) {
            return MAP.subMap(fromKey, true, toKey, true);
        }
        
        private static final File FILE = new File("./data/reputation.txt");
        private static Writer WRITER = null;
        private static final LinkedList<String> LIST = new LinkedList<>();
        private static final Semaphore SEMAPHORE = new Semaphore(0);
    
        private static void append(String line) {
            if (SEMAPHORE.tryAcquire()) {
                try {
                    writeList();
                    WRITER.append(line);
                    WRITER.write('\n');
                    WRITER.flush();
                } catch (Exception ex) {
                    Server.logError(ex);
                } finally {
                    SEMAPHORE.release();
                }
            } else {
                LIST.offer(line);
            }
        }

        private static void writeList() {
            try {
                String line;
                while ((line = LIST.poll()) != null) {
                    WRITER.write(line);
                    WRITER.write('\n');
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }

        private static void startWriter() {
            try {
                WRITER = new FileWriter(FILE, true);
                writeList();
                if (Core.isRunning()) {
                    WRITER.flush();
                } else {
                    WRITER.close();
                }
            } catch (Exception ex) {
                Server.logError(ex);
            } finally {
                if (Core.isRunning()) {
                    SEMAPHORE.release();
                }
            }
        }

        public static void load() {
            long time = System.currentTimeMillis();
            if (FILE.exists()) {
                String line;
                try (BufferedReader reader = new BufferedReader(new FileReader(FILE))) {
                    while ((line = reader.readLine()) != null) {
                        try {
                            StringTokenizer tokenizer = new StringTokenizer(line, " ");
                            String token = tokenizer.nextToken();
                            if (token.equals("ADDR") && tokenizer.countTokens() == 7) {
                                String key = tokenizer.nextToken();
                                Long creation = Core.parseLong(tokenizer.nextToken(), 32);
                                Long lastQuery = Core.parseLong(tokenizer.nextToken(), 32);
                                Status status = Status.parse(tokenizer.nextToken());
                                NormalDistribution frequency = newNormalDistribution(
                                        tokenizer.nextToken(),
                                        tokenizer.nextToken()
                                );
                                boolean good = Boolean.parseBoolean(tokenizer.nextToken());
                                Distribution distribution = newDistribution(
                                        creation, lastQuery,
                                        status, frequency, good
                                );
                                if (distribution == null) {
                                    Server.logError(line);
                                } else {
                                    MAP.put(key, distribution);
                                }
                            } else if (token.equals("ADDH") && tokenizer.countTokens() == 2) {
                                String key = tokenizer.nextToken();
                                Long value = Core.parseLong(tokenizer.nextToken(), 32);
                                Distribution distribution = MAP.get(key);
                                if (distribution == null) {
                                    Server.logError(line);
                                } else if (value == null) {
                                    Server.logError(line);
                                } else {
                                    distribution.hamSet.add(value);
                                }
                            } else if (token.equals("ADDS") && tokenizer.countTokens() == 2) {
                                String key = tokenizer.nextToken();
                                Long value = Core.parseLong(tokenizer.nextToken(), 32);
                                Distribution distribution = MAP.get(key);
                                if (distribution == null) {
                                    Server.logError(line);
                                } else if (value == null) {
                                    Server.logError(line);
                                } else {
                                    distribution.spamSet.add(value);
                                }
                            } else if (token.equals("DELR") && tokenizer.countTokens() == 1) {
                                String key = tokenizer.nextToken();
                                MAP.remove(key);
                            } else if (token.equals("DELH") && tokenizer.countTokens() == 2) {
                                String key = tokenizer.nextToken();
                                Long value = Core.parseLong(tokenizer.nextToken(), 32);
                                Distribution distribution = MAP.get(key);
                                if (distribution == null) {
                                    Server.logError(line);
                                } else if (value == null) {
                                    Server.logError(line);
                                } else {
                                    distribution.hamSet.remove(value);
                                }
                            } else if (token.equals("DELS") && tokenizer.countTokens() == 2) {
                                String key = tokenizer.nextToken();
                                Long value = Core.parseLong(tokenizer.nextToken(), 32);
                                Distribution distribution = MAP.get(key);
                                if (distribution == null) {
                                    Server.logError(line);
                                } else if (value == null) {
                                    Server.logError(line);
                                } else {
                                    distribution.spamSet.remove(value);
                                }
                            }
                        } catch (Exception ex) {
                            Server.logError(line);
                            Server.logError(ex);
                        }
                    }
                    Server.logLoad(time, FILE);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            } else {
                try {
                    File file = new File("./data/distribution.map");
                    if (file.exists()) {
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
                                    MAP.put(key, distribution);
                                }
                            }
                        }
                        Server.logLoad(time, file);
                    }
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
            startWriter();
        }

        public static boolean store() {
            try {
                long time = System.currentTimeMillis();
                SEMAPHORE.acquire();
                try {
                    WRITER.close();
                    Path source = FILE.toPath();
                    Path temp = source.resolveSibling('.' + FILE.getName());
                    try (FileWriter writer = new FileWriter(temp.toFile())) {
                        for (String key : keySet()) {
                            Distribution distribution = getExact(key);
                            if (distribution != null) {
                                if (distribution.isExpired14()) {
                                    drop(key);
                                } else {
                                    distribution.dropExpiredQuery();
                                    distribution.store(key, writer);
                                }
                            }
                        }
                    }
                    Files.move(temp, source, REPLACE_EXISTING);
                    Server.logStore(time, FILE);
                    File file = new File("./data/distribution.map");
                    file.delete();
                    return true;
                } finally {
                    startWriter();
                }
            } catch (Exception ex) {
                Server.logError(ex);
                return false;
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
            if (isValidIP(value)) {
                String ip = Subnet.normalizeIP(value);
                distribution = getExact(ip);
                if (distribution != null) {
                    map.put(ip, distribution);
                }
            } else if (isValidCIDR(value)) {
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
            } else if (isHostname(value)) {
                String host = Domain.normalizeHostname(value, true);
                do {
                    int index = host.indexOf('.') + 1;
                    host = host.substring(index);
                    if ((distribution = getExact('.' + host)) != null) {
                        map.put('.' + host, distribution);
                    } else if ((distribution = getExact('@' + host)) != null) {
                        map.put('@' + host, distribution);
                    }
                    System.out.println(host);
                } while (host.contains(".") && !Domain.isRootDomain(host));
            } else if (isValidEmail(value)) {
                value = Domain.normalizeEmail(value);
                distribution = getExact(value);
                if (distribution != null) {
                    map.put(value, distribution);
                }
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
            if (key == null) {
                return null;
            } else {
                if (isValidEmail(key)) {
                    key = Domain.normalizeEmail(key);
                }
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
                if (isValidIPv4(key)) {
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
                if (isValidIPv6(key)) {
                    Distribution distribution = getExact(key);
                    if (distribution != null) {
                        distributionMap.put(key, distribution);
                    }
                }
            }
            return distributionMap;
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
    

    public static TreeMap<String,Distribution> getDistributionMap() {
        return CacheDistribution.getTreeMap();
    }
    
    public static Distribution getDistribution(String token) {
        return CacheDistribution.get(token, false);
    }
    
    public static Float getSpamProbability(String token, int limit) {
        Distribution distribution = CacheDistribution.get(token, false);
        if (distribution == null) {
            return null;
        } else {
            return distribution.getSpamProbability(token, limit);
        }
    }
    
    public static Distribution getDistribution(String token, boolean create) {
        return CacheDistribution.get(token, create);
    }
    
    public static float getSpamProbability(String token) {
        if (token == null) {
            return 0.0f;
        } else {
            Distribution distribution = CacheDistribution.get(token, false);
            if (distribution == null) {
                return 0.0f;
            } else {
                return distribution.getSpamProbability(token);
            }
        }
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
    
    private static final Regex WHOIS_PATTERN = new Regex("^"
            + "WHOIS(/[a-z-]+)+((=[a-zA-Z0-9@/.-]+)|((<|>)[0-9]+))"
            + "$"
    );

    private static boolean isWHOIS(String token) {
        return WHOIS_PATTERN.matches(token);
    }
    
    private static final Regex REGEX_PATTERN = new Regex("^"
            + "REGEX=[^ ]+"
            + "$"
    );

    public static boolean isREGEX(String token) {
        return REGEX_PATTERN.matches(token);
    }
    
    private static boolean isDNSBL(String token) {
        if (token.startsWith("DNSBL=") && token.contains(";")) {
            int index1 = token.indexOf('=');
            int index2 = token.indexOf(';');
            String server = token.substring(index1 + 1, index2);
            String value = token.substring(index2 + 1);
            return isHostname(server) && isValidIP(value);
        } else {
            return false;
        }
    }
    
    private static final Regex CIDR_PATTERN = new Regex("^"
            + "CIDR=("
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
            + ")"
            + "$"
    );

    private static boolean isCIDR(String token) {
        return CIDR_PATTERN.matches(token);
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
        return normalizeToken(
                token, true, true, true, true,
                true, true, true, true, false
        );
    }

    public static String normalizeToken(
            String token,
            boolean canWHOIS,
            boolean canREGEX,
            boolean canCIDR,
            boolean canDNSBL,
            boolean canHREF,
            boolean canNOTPASS,
            boolean canExecutable,
            boolean canURL,
            boolean canFAIL
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
        } else if (canCIDR && isValidIPv4(token)) {
            return "CIDR=" + SubnetIPv4.normalizeIPv4(token) + "/32";
        } else if (canCIDR && isValidIPv6(token)) {
            return "CIDR=" + SubnetIPv6.normalizeIPv6(token) + "/128";
        } else if (canWHOIS && Owner.isOwnerID(token)) {
            return "WHOIS/ownerid=" + Owner.normalizeID(token);
        } else if (canCIDR && isValidCIDR(token)) {
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
            if (value.length() == 0) {
                return null;
            } else if (Owner.isOwnerID(value)) {
                return "HREF=" + Owner.normalizeID(value);
            } else {
                return "HREF=" + normalizeToken(
                        value, false, false, false, false,
                        false, false, false, false, false
                );
            }
        } else if (canExecutable && Core.isExecutableSignature(token.toLowerCase())) {
            return token.toLowerCase();
        } else if (canURL && Core.isSignatureURL(token.toLowerCase())) {
            return token.toLowerCase();
        } else if (canURL && Core.isValidURL(token)) {
            return Core.getSignatureURL(token);
        } else {
            token = Core.removerAcentuacao(token);
            String recipient = "";
            if (token.contains(">")) {
                int index = token.indexOf('>');
                recipient = token.substring(index + 1);
                token = token.substring(0, index);
                if (recipient.equals("@")) {
                    recipient = '>' + recipient;
                } else if (isValidEmail(recipient)) {
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
                } else if (qualif.equals(";NONE")) {
                    token = token.substring(0, index);
                } else if (qualif.equals(";BULK")) {
                    token = token.substring(0, index);
                } else if (qualif.equals(";SOFTFAIL")) {
                    return null;
                } else if (qualif.equals(";NEUTRAL")) {
                    return null;
                } else if (canFAIL && qualif.equals(";FAIL")) {
                    token = token.substring(0, index);
                } else if (canNOTPASS && qualif.equals(";NOTPASS")) {
                    token = token.substring(0, index);
                } else if (isHostname(qualif.substring(1))) {
                    qualif = ";" + Domain.normalizeHostname(qualif.substring(1), false);
                    token = token.substring(0, index);
                } else if (isValidIP(qualif.substring(1))) {
                    qualif = ";" + Subnet.normalizeIP(qualif.substring(1));
                    token = token.substring(0, index);
                } else {
                    // Sintaxe com erro.
                    return null;
                }
            }
            if (Domain.isMailFrom(token)) {
                token = Domain.normalizeEmail(token);
                return token + qualif + recipient;
            } else if (token.endsWith("@")) {
                return token.toLowerCase() + qualif + recipient;
            } else if (token.startsWith("@") && Domain.containsDomain(token.substring(1))) {
                return token.toLowerCase() + qualif + recipient;
            } else if (!token.contains("@") && Domain.containsDomain(token)) {
                return Domain.extractHost(token, true) + qualif + recipient;
            } else if (token.startsWith(".") && Domain.containsDomain(token.substring(1))) {
                return Domain.extractHost(token, true) + qualif + recipient;
            } else if (isValidIP(token)) {
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

        private static boolean add(
                String hostname,
                String spf
        ) throws ProcessException {
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
    public static void store() {
        CacheSPF.store();
        CacheDistribution.store();
        CacheGuess.store();
    }

    /**
     * Carregamento de cache do disco.
     */
    public static void load() {
        CacheSPF.load();
        CacheDistribution.load();
        CacheGuess.load();
    }
    
    public static void loadSPF() {
        CacheSPF.load();
    }
        
    public static String processPostfixDATA(
            Client client,
            User user,
            String ip,
            String sender,
            String helo,
            String instance
            ) throws ProcessException {
        if (user == null) {
            return "action=DUNNO\n\n";
        } else if (instance == null) {
            return "action=DUNNO\n\n";
        } else {
            for (long time : user.getTimeKeySet().descendingSet()) {
                Query query = user.getQuery(time);
                if (query.isInstance(instance)) {
                    if (query.isClient(client)) {
                        if (query.isIP(ip)) {
                            if (query.isMailFrom(sender)) {
                                if (query.isHELO(helo)) {
                                    if (query.isFlagged()) {
                                        return "action=PREPEND X-Spam-Flag: YES\n\n";
                                    } else if (query.isHolding()) {
                                        return "action=HOLD\n\n";
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return "action=DUNNO\n\n";
        }
    }

    public static String processPostfixRCPT(
            InetAddress clientIP,
            Client client,
            User user,
            String ip,
            String sender,
            String helo,
            String recipient,
            String instance,
            LinkedList<User> userResult,
            TreeSet<Long> timeKeySet
            ) throws ProcessException {
        if (sender == null) {
            sender = null;
        } else if (sender.trim().length() == 0) {
            sender = null;
        } else if (Domain.isMailFrom(sender)) {
            sender = sender.toLowerCase();
        } else if (Block.isBanned(client, null, ip, helo, null, sender, "NONE", "@")) {
            Client.ban(client, ip);
            SPF.addComplainSafe(ip);
            Abuse.addHarmful(ip, null);
            CIDR.addHarmful(ip);
            return "action=554 5.7.1 SPFBL "
                    + "you was banned. "
                    + "See http://spfbl.net/en/feedback\n\n";
        } else {
            return "action=554 5.7.1 SPFBL " + sender + " "
                    + "is not a valid e-mail address. "
                    + "See http://spfbl.net/en/feedback\n\n";
        }
        String subaddress = null;
        if (recipient == null) {
            recipient = null;
        } else if (recipient.trim().length() == 0) {
            recipient = null;
        } else if (isValidRecipient(recipient)) {
            recipient = recipient.toLowerCase();
            int index1 = recipient.indexOf('+');
            int index2 = recipient.lastIndexOf('@');
            if (index1 > 0 && index2 > 0) {
                // Subaddress Extension.
                // https://tools.ietf.org/html/rfc5233.html
                String part = recipient.substring(0, index1);
                subaddress = recipient.substring(index1+1, index2);
                String domain = recipient.substring(index2);
                recipient = part + domain;
            }
        } else {
            return "action=554 5.7.1 SPFBL " + recipient + " "
                    + "is not a valid e-mail address. "
                    + "See http://spfbl.net/en/feedback\n\n";
        }
        if (!isHostname(helo)) {
            helo = null;
        }
        Long recipientTrapTime = Trap.getTimeRecipient(
                client, user, recipient
        );
        ip = SubnetIPv6.tryTransformToIPv4(ip);
        ip = Subnet.normalizeIP(ip);
        if (!isValidIP(ip)) {
            return "action=554 5.7.1 SPFBL "
                    + ip + " is not a valid public IP. "
                    + "See http://spfbl.net/en/feedback\n\n";
        } else if (Subnet.isReservedIP(ip)) {
            // Message from LAN.
            if (recipientTrapTime == null) {
                return "action=DUNNO\n\n";
            } else {
                return "action=550 5.1.1 SPFBL the account "
                        + "that you tried to reach does not exist. "
                        + "See http://spfbl.net/en/feedback\n\n";
            }
        } else if (recipient != null && !isValidEmail(recipient)) {
            return "action=554 5.7.1 SPFBL "
                    + recipient + " is not a valid recipient. "
                    + "See http://spfbl.net/en/feedback\n\n";
        } else if (client != null && client.containsFull(ip)) {
            // Message from LAN.
            if (recipientTrapTime == null) {
                return "action=DUNNO\n\n";
            } else {
                return "action=550 5.1.1 SPFBL the account "
                        + "that you tried to reach does not exist. "
                        + "See http://spfbl.net/en/feedback\n\n";
            }
        } else {
            try {
                TreeSet<String> tokenSet = new TreeSet<>();
                if (!Ignore.containsIPorFQDN(ip)) {
                    tokenSet.add(ip);
                }
                if (isValidEmail(recipient)) {
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
                        if (index > 0) {
                            String postmaster = "postmaster" + recipient.substring(index);
                            User postmasterUser = User.get(postmaster);
                            if (postmasterUser != null) {
                                user = postmasterUser;
                            }
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
                String fqdn;
                if (!isHostname(helo)) {
                    fqdn = FQDN.getFQDN(ip, false);
                } else if (Generic.containsGenericFQDN(helo)) {
                    fqdn = FQDN.getFQDN(ip, false);
                } else if (FQDN.isFQDN(ip, helo)) {
                    fqdn = Domain.normalizeHostname(helo, true);
                } else if (FQDN.addFQDN(ip, helo, true)) {
                    fqdn = Domain.normalizeHostname(helo, true);
                } else {
                    fqdn = FQDN.getFQDN(ip, false);
                }
                if (fqdn != null) {
                    fqdn = fqdn.toLowerCase();
                    tokenSet.add(fqdn);
                    if (Provider.containsFQDN(fqdn)) {
                        Block.clearFQDN(null, fqdn, Core.getAdminEmail());
                        Block.clearCIDR(null, ip, Core.getAdminEmail());
                    } else if (Ignore.containsFQDN(fqdn)) {
                        Block.clearFQDN(null, fqdn, Core.getAdminEmail());
                        Block.clearCIDR(null, ip, Core.getAdminEmail());
                    }
                }
                if (White.isDesactive(client, user, ip, fqdn, recipient)) {
                    if (recipientTrapTime == null) {
                        return "action=DUNNO\n\n";
                    } else {
                        return "action=550 5.1.1 SPFBL the account "
                                + "that you tried to reach does not exist. "
                                + "See http://spfbl.net/en/feedback\n\n";
                    }
                } else if (fqdn == null) {
                    Server.logInfo("no FQDN was found for " + ip + ".");
                } else if (Domain.isOfficialTLD(fqdn)) {
                    return "action=554 5.7.1 SPFBL "
                            + fqdn + " is a reserved domain. "
                            + "See http://spfbl.net/en/feedback\n\n";
                }
                String result;
                LinkedList<String> logList = new LinkedList<>();
                SPF spf;
                if (sender == null) {
                    spf = null;
                    result = "NONE";
                } else if (Domain.isOfficialTLD(sender) && !Ignore.contains(sender)) {
                    spf = null;
                    result = "NONE";
                } else if (Generic.containsGeneric(sender)) {
                    // Don't query SPF from generic domain to avoid high latency.
                    spf = null;
                    result = "NONE";
                } else if ((spf = CacheSPF.getSafe(sender)) == null) {
                    result = "NONE";
                } else if (spf.isInexistent()) {
                    result = "SOFTFAIL";
                } else {
                    result = spf.getResultSafe(ip, sender, helo, logList);
                }
                String origem;
                String fluxo;
                String mx = Domain.extractHost(sender, true);
                if (recipient != null && result.equals("PASS")) {
                    if (recipient.endsWith(mx)) {
                        // Message from same domain.
                        if (recipientTrapTime == null) {
                            return "action=DUNNO\n\n";
                        } else {
                            return "action=550 5.1.1 SPFBL the account "
                                    + "that you tried to reach does not exist. "
                                    + "See http://spfbl.net/en/feedback\n\n";
                        }
                    } else if (
                            recipient.equals(Core.getAbuseEmail()) &&
                            User.exists(sender, "postmaster" + mx)
                            ) {
                        // Message to abuse.
                        if (recipientTrapTime == null) {
                            return "action=DUNNO\n\n";
                        } else {
                            return "action=550 5.1.1 SPFBL the account "
                                    + "that you tried to reach does not exist. "
                                    + "See http://spfbl.net/en/feedback\n\n";
                        }
                    }
                }
                if (result.equals("PASS") || (sender != null && Provider.containsFQDN(fqdn))) {
                    // Quando fo PASS, significa que o domínio
                    // autorizou envio pelo IP, portanto o dono dele
                    // é responsavel pelas mensagens.
                    if (!Provider.containsExact(mx)) {
                        // Não é um provedor então
                        // o MX deve ser listado.
                        tokenSet.add(mx);
                        origem = mx;
                    } else if (isValidEmail(sender)) {
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
                        tokenSet.add(Domain.normalizeEmail(sender));
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
                } else if (fqdn == null) {
                    origem = (sender == null ? "" : sender + '>') + ip;
                    fluxo = origem + ">" + recipient;
                } else {
                    String dominio = Domain.extractDomainSafe(fqdn, true);
                    origem = (sender == null ? "" : sender + '>') + (dominio == null ? fqdn : dominio.substring(1));
                    fluxo = origem + ">" + recipient;
                }
                if (Core.isMyHostname(fqdn)) {
                    if (Core.isAdminEmail(sender, result)) {
                        return "action=DUNNO\n\n";
                    }
                }
                Flag envelopeFlag;
                String blockKey;
                int usingSince = usingSince(helo, fqdn, sender);
                if (!Core.isRunning() && user != null && user.usingHeader()) {
                    long timeKey = SPF.addQuery(
                            clientIP, client, user, ip, helo, fqdn, sender,
                            result, recipient, subaddress, tokenSet,
                            "GREYLIST", "SYSTEM_SHUTDOWN"
                    );
                    timeKeySet.add(timeKey);
                    return "action=451 4.7.1 SPFBL you are greylisted. "
                            + "See http://spfbl.net/en/feedback\n\n";
                 } else if (White.contains(client, user, ip, sender, fqdn, result, recipient, subaddress)) {
                    if (recipientTrapTime == null) {
                        Object[] resultSet = SPF.addQueryHam(
                                clientIP, client, user, ip, helo, fqdn, sender,
                                result, recipient, subaddress, tokenSet,
                                "WHITE", "ORIGIN_WHITELISTED"
                        );
                        Long timeKey = (Long) resultSet[0];
                        timeKeySet.add(timeKey);
                        String ticket = (String) resultSet[1];
                        Block.clear(timeKey, client, user, ip, helo, sender, fqdn, result, recipient, "WHITE");
                        String url = Core.getURL(user);
                        if (user != null && !user.usingHeader()) {
                            if (White.containsKey(user, ip, fqdn, sender, result)) {
                                Reputation.addBeneficial(client, user, ip, fqdn, helo, sender, result, recipient);
                            } else {
                                Reputation.addDesirable(client, user, ip, fqdn, helo, sender, result, recipient);
                            }
                        }
                        return "action=PREPEND "
                                + "Received-SPFBL: " + result + " "
                                + (url == null ? ticket : url + ticket) + "\n\n";
                    } else {
                        Object[] resultSet = SPF.getTicket(
                                clientIP, client, user, ip, helo, fqdn, sender,
                                result, recipient, subaddress, tokenSet,
                                "INEXISTENT", "RECIPIENT_INEXISTENT"
                        );
                        Long timeKey = (Long) resultSet[0];
                        timeKeySet.add(timeKey);
                        Reputation.addUnacceptable(client, user, ip, fqdn, helo, sender, result, recipient);
                        return "action=550 5.1.1 SPFBL the account "
                                + "that you tried to reach does not exist. "
                                + "See http://spfbl.net/en/feedback\n\n";
                    }
                } else if (Block.containsCIDR(ip) && Generic.isDynamicIP(ip)) {
                    Client.banDynamic(client, ip);
                    long time = Server.getNewUniqueTime();
                    SPF.setSpam(time, tokenSet);
                    Abuse.addHarmful(ip, fqdn);
                    CIDR.addHarmful(ip);
                    return "action=554 5.7.1 SPFBL "
                            + "you are permanently blocked. "
                            + "See http://spfbl.net/en/feedback\n\n";
                } else if (Block.isBanned(client, user, ip, helo, fqdn, sender, result, recipient)) {
                    Client.ban(client, ip);
                    Object[] resultSet = null;
                    if (user != null) {
                        if (Block.ban(client, user, ip, helo, sender, fqdn, result, recipient)) {
                            resultSet = SPF.addQuerySpam(
                                    clientIP, client, user, ip, helo, fqdn, sender,
                                    result, recipient, subaddress, tokenSet,
                                    "BLOCK", "ORIGIN_BANNED"
                            );
                        }
                    }
                    Long timeKey = (resultSet == null ? Server.getNewUniqueTime() : (Long) resultSet[0]);
                    timeKeySet.add(timeKey);
                    User.Query queryLocal = (resultSet == null ? null : (User.Query) resultSet[1]);
                    if (queryLocal == null) {
                        setSpam(timeKey, tokenSet);
                        Abuse.reportAbuse(
                                timeKey, clientIP, client, user,
                                sender, recipient,
                                ip, fqdn, result, null
                        );
                    } else {
                        Abuse.offer(timeKey, queryLocal);
                    }
                    Reputation.addHarmful(client, user, ip, fqdn, helo, sender, result, recipient);
                    return "action=554 5.7.1 SPFBL "
                            + "you was banned. "
                            + "See http://spfbl.net/en/feedback\n\n";
                } else if ((blockKey = Block.find(client, user, ip, sender, fqdn, result, recipient, true, true, true, true, true, true)) != null) {
                    if (Reputation.isHarmful(ip, fqdn, helo, sender, result)) {
                        Object[] resultSet = SPF.addQuerySpam(
                                clientIP, client, user, ip, helo, fqdn, sender,
                                result, recipient, subaddress, tokenSet,
                                "BLOCK", "ENVELOPE_BLOCKED;" + blockKey
                        );
                        Long timeKey = (Long) resultSet[0];
                        timeKeySet.add(timeKey);
                        User.Query queryLocal = (User.Query) resultSet[1];
                        if (queryLocal == null) {
                            Abuse.reportAbuse(
                                    timeKey, clientIP, client, user,
                                    sender, recipient,
                                    ip, fqdn, result, null
                            );
                        } else {
                            Abuse.offer(timeKey, queryLocal);
                        }
                        String url = Core.getUnblockURL(
                                client, user, ip,
                                sender, fqdn, recipient
                        );
                        Block.ban(
                                client, user, ip, helo, sender,
                                fqdn, result, recipient
                        );
                        Reputation.addHarmful(
                                client, user, ip, fqdn, helo, sender, result, recipient
                        );
                        if (url == null) {
                            return "action=554 5.7.1 SPFBL "
                                    + "you are permanently blocked. "
                                    + "See http://spfbl.net/en/feedback\n\n";
                        } else {
                            return "action=554 5.7.1 SPFBL "
                                + "BLOCKED " + url + "\n\n";
                        }
                    } else if (fqdn == null && !result.equals("PASS") && !isHostname(helo)) {
                        Object[] resultSet = SPF.addQuerySpam(
                                clientIP, client, user, ip, helo, fqdn, sender,
                                result, recipient, subaddress, tokenSet,
                                "BLOCK", "HELO_ANONYMOUS"
                        );
                        Long timeKey = (Long) resultSet[0];
                        timeKeySet.add(timeKey);
                        User.Query queryLocal = (User.Query) resultSet[1];
                        boolean banned = true;
                        String url = null;
                        if (queryLocal == null) {
                            Abuse.reportAbuse(
                                    timeKey, clientIP, client, user,
                                    sender, recipient,
                                    ip, fqdn, result, null
                            );
                        } else if (queryLocal.blockKey(timeKey, "INVALID")) {
                            Abuse.offer(timeKey, queryLocal);
                            url = Core.getUnblockURL(
                                    client, user, ip,
                                    sender, fqdn, recipient
                            );
                        } else {
                            Abuse.offer(timeKey, queryLocal);
                            banned = Block.ban(
                                    client, user, ip, helo, sender,
                                    fqdn, result, recipient
                            );
                        }
                        if (banned) {
                            Abuse.addHarmful(ip, fqdn);
                            CIDR.addHarmful(ip);
                        } else {
                            Abuse.addUndesirable(ip, fqdn);
                            CIDR.addUndesirable(ip);
                        }
                        if (url == null) {
                            return "action=554 5.7.1 SPFBL "
                                    + "you are permanently blocked. "
                                    + "See http://spfbl.net/en/feedback\n\n";
                        } else {
                            return "action=554 5.7.1 SPFBL "
                                + "BLOCKED " + url + "\n\n";
                        }
                    } else if (sender != null && spf != null && spf.isInexistent()) {
                        Object[] resultSet = SPF.addQuerySpam(
                                clientIP, client, user, ip, helo, fqdn, sender,
                                result, recipient, subaddress, tokenSet,
                                "BLOCK", "SPF_NXDOMAIN"
                        );
                        Long timeKey = (Long) resultSet[0];
                        timeKeySet.add(timeKey);
                        User.Query queryLocal = (User.Query) resultSet[1];
                        String url = null;
                        if (recipientTrapTime == null) {
                            url = Core.getUnblockURL(
                                    client, user, ip,
                                    sender, fqdn, recipient
                            );
                        }
                        boolean banned = true;
                        if (queryLocal == null) {
                            Abuse.reportAbuse(
                                    timeKey, clientIP, client, user,
                                    sender, recipient,
                                    ip, fqdn, result, url
                            );
                        } else if (queryLocal.blockKey(timeKey, "NONE")) {
                            Abuse.offer(timeKey, queryLocal);
                        } else if (queryLocal.blockKey(timeKey, sender + ";NXDOMAIN")) {
                            Abuse.offer(timeKey, queryLocal);
                        } else if (spf.isDefinitelyInexistent()) {
                            Abuse.offer(timeKey, queryLocal);
                            banned = Block.ban(
                                    client, user, ip, helo, sender,
                                    fqdn, result, recipient
                            );
                            url = null;
                        }
                        if (banned) {
                            Reputation.addHarmful(
                                    client, user, ip, fqdn, helo, sender, result, recipient
                            );
                        } else {
                            Reputation.addUndesirable(
                                    client, user, ip, fqdn, helo, sender, result, recipient
                            );
                        }
                        if (url == null) {
                            return "action=554 5.7.1 SPFBL "
                                + "you are permanently blocked. "
                                    + "See http://spfbl.net/en/feedback\n\n";
                        } else {
                            return "action=554 5.7.1 SPFBL "
                                + "BLOCKED " + url + "\n\n";
                        }
                    } else if (recipientTrapTime == null) {
                        Action action = client == null ? Action.REJECT : client.getActionBLOCK();
                        if (action == Action.REJECT) {
                            Object[] resultSet = SPF.addQuerySpam(
                                    clientIP, client, user, ip, helo, fqdn, sender,
                                    result, recipient, subaddress, tokenSet,
                                    "BLOCK", "ENVELOPE_BLOCKED;" + blockKey
                            );
                            Long timeKey = (Long) resultSet[0];
                            timeKeySet.add(timeKey);
                            User.Query queryLocal = (User.Query) resultSet[1];
                            if (queryLocal != null && queryLocal.needHeader()) {
                                action = client == null ? Action.FLAG : client.getActionRED();
                                if (action == Action.HOLD) {
                                    String url = Core.getURL(user);
                                    String ticket = SPF.createTicket(timeKey, tokenSet);
                                    queryLocal.setPostfixHOLD(instance);
                                    return "action=PREPEND Received-SPFBL: HOLD "
                                            + (url == null ? ticket : url + ticket) + "\n\n";
                                } else {
                                    String url = Core.getURL(user);
                                    String ticket = SPF.createTicket(timeKey, tokenSet);
                                    queryLocal.setPostfixFLAG(instance);
                                    return "action=PREPEND Received-SPFBL: FLAG "
                                            + (url == null ? ticket : url + ticket) + "\n\n";
                                }
                            } else {
                                String url = Core.getUnblockURL(
                                        client, user, ip,
                                        sender, fqdn, recipient
                                );
                                boolean banned = false;
                                if (queryLocal == null) {
                                    Abuse.reportAbuse(
                                            timeKey, clientIP, client, user,
                                            sender, recipient,
                                            ip, fqdn, result, url
                                    );
                                } else if (NoReply.containsFQDN(fqdn)) {
                                    Abuse.offer(timeKey, queryLocal);
                                    banned = Block.ban(
                                            client, user, ip, helo, sender,
                                            fqdn, result, recipient
                                    );
                                    url = null;
                                } else {
                                    Abuse.offer(timeKey, queryLocal);
                                }
                                if (banned) {
                                    Reputation.addHarmful(
                                            client, user, ip, fqdn, helo, sender, result, recipient
                                    );
                                } else {
                                    Reputation.addUndesirable(
                                            client, user, ip, fqdn, helo, sender, result, recipient
                                    );
                                }
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
                            String url = Core.getURL(user);
                            String ticket = SPF.getPostfixTicketFLAG(
                                    clientIP, client, user, ip, helo, fqdn, sender,
                                    result, recipient, subaddress, instance, tokenSet,
                                    "ENVELOPE_BLOCKED;" + blockKey
                            );
                            return "action=PREPEND Received-SPFBL: FLAG "
                                    + (url == null ? ticket : url + ticket) + "\n\n";
                        } else if (action == Action.HOLD) {
                            String url = Core.getURL(user);
                            String ticket = SPF.getPostfixTicketHOLD(
                                    clientIP, client, user, ip, helo, fqdn, sender,
                                    result, recipient, subaddress, instance, tokenSet,
                                    "ENVELOPE_BLOCKED;" + blockKey
                            );
                            return "action=PREPEND Received-SPFBL: HOLD "
                                    + (url == null ? ticket : url + ticket) + "\n\n";
                        } else {
                            return "action=WARN undefined action.\n\n";
                        }
                    } else {
                        Object[] resultSet = SPF.addQuerySpam(
                                clientIP, client, user, ip, helo, fqdn, sender,
                                result, recipient, subaddress, tokenSet,
                                "BLOCK", "RECIPIENT_INEXISTENT"
                        );
                        Long timeKey = (Long) resultSet[0];
                        timeKeySet.add(timeKey);
                        User.Query queryLocal = (User.Query) resultSet[1];
                        if (queryLocal != null && !queryLocal.needHeader() && queryLocal.isHarmful()) {
                            queryLocal.blockKey(timeKey, recipient + ";INEXISTENT");
                        }
                        boolean banned = false;
                        if (queryLocal == null) {
                            Abuse.reportAbuse(
                                    timeKey, clientIP, client, user,
                                    sender, recipient,
                                    ip, fqdn, result, null
                            );
                        } else if (System.currentTimeMillis() > recipientTrapTime) {
                            // Spamtrap.
                            Abuse.offer(timeKey, queryLocal);
                            banned = Block.ban(
                                    client, user, ip, helo, sender,
                                    fqdn, result, recipient
                            );
                        } else {
                            Abuse.offer(timeKey, queryLocal);
                        }
                        if (banned) {
                            Reputation.addHarmful(
                                    client, user, ip, fqdn, helo, sender, result, recipient
                            );
                        } else {
                            Reputation.addUndesirable(
                                    client, user, ip, fqdn, helo, sender, result, recipient
                            );
                        }
                        return "action=554 5.7.1 SPFBL "
                                + "you are permanently blocked. "
                                + "See http://spfbl.net/en/feedback\n\n";
                    }
                } else if (sender != null && spf != null && spf.isDefinitelyInexistent()) {
                    Object[] resultSet = SPF.addQuerySpam(
                            clientIP, client, user, ip, helo, fqdn, sender,
                            result, recipient, subaddress, tokenSet,
                            "NXDOMAIN", "SPF_NXDOMAIN"
                    );
                    Long timeKey = (Long) resultSet[0];
                    timeKeySet.add(timeKey);
                    if (Reputation.isUndesirable(ip, fqdn, helo, sender, result, user, recipient)) {
                        Block.addBlockKey(
                                timeKey, client, user, ip, helo, sender,
                                fqdn, result, null, "NXDOMAIN"
                        );
                    }
                    Reputation.addUnacceptable(client, user, ip, fqdn, helo, sender, result, recipient);
                    return "action=554 5.7.1 SPFBL "
                            + "sender has non-existent internet domain. "
                            + "See http://spfbl.net/en/feedback\n\n";
                } else if (result.equals("FAIL")) {
                    boolean hasActionHOLD = client == null ? false : client.hasActionHOLD();
                    boolean usingHeader = user == null ? false : user.usingHeader();
                    if (hasActionHOLD && usingHeader) {
                        String url = Core.getURL(user);
                        String ticket = SPF.getPostfixTicketHOLD(
                                clientIP, client, user, ip, helo, fqdn, sender,
                                result, recipient, subaddress, instance, tokenSet,
                                null
                        );
                        return "action=PREPEND Received-SPFBL: HOLD "
                                + (url == null ? ticket : url + ticket) + "\n\n";
                    } else {
                        Object[] resultSet = SPF.addQuerySpam(
                                clientIP, client, user, ip, helo, fqdn, sender,
                                result, recipient, subaddress, tokenSet,
                                "FAIL", "SPF_FAIL"
                        );
                        Long timeKey = (Long) resultSet[0];
                        timeKeySet.add(timeKey);
                        if (Reputation.isUndesirable(ip, fqdn, helo, sender, result, user, recipient)) {
                            Block.addBlockKey(
                                    timeKey, client, user, ip, helo, sender,
                                    fqdn, result, null, "FAIL"
                            );
                        }
                        Reputation.addUnacceptable(client, user, ip, fqdn, helo, sender, result, recipient);
                        return "action=554 5.7.1 SPFBL "
                                + sender + " is not allowed to "
                                + "send mail from " + ip + ". "
                                + "See http://spfbl.net/en/feedback\n\n";
                    }
                } else if (sender != null && !Domain.isMailFrom(sender)) {
                    boolean hasActionHOLD = client == null ? false : client.hasActionHOLD();
                    boolean usingHeader = user == null ? false : user.usingHeader();
                    if (hasActionHOLD && usingHeader) {
                        String url = Core.getURL(user);
                        String ticket = SPF.getPostfixTicketHOLD(
                                clientIP, client, user, ip, helo, fqdn, sender,
                                result, recipient, subaddress, instance, tokenSet,
                                null
                        );
                        return "action=PREPEND Received-SPFBL: HOLD "
                                + (url == null ? ticket : url + ticket) + "\n\n";
                    } else {
                        Object[] resultSet = SPF.addQuerySpam(
                                clientIP, client, user, ip, helo, fqdn, sender,
                                result, recipient, subaddress, tokenSet,
                                "INVALID", "ENVELOPE_INVALID;SENDER"
                        );
                        Long timeKey = (Long) resultSet[0];
                        timeKeySet.add(timeKey);
                        if (Reputation.isUndesirable(ip, fqdn, helo, sender, result, user, recipient)) {
                            Block.addBlockKey(
                                    timeKey, client, user, ip, helo, sender,
                                    fqdn, result, null, "INVALID"
                            );
                        }
                        Reputation.addUnacceptable(client, user, ip, fqdn, helo, sender, result, recipient);
                        return "action=554 5.7.1 SPFBL "
                                + sender + " is not a valid e-mail address. "
                                + "See http://spfbl.net/en/feedback\n\n";
                    }
                } else if (sender != null && !result.equals("PASS") && Domain.isOfficialTLD(sender)) {
                    Object[] resultSet = SPF.addQuerySpam(
                            clientIP, client, user, ip, helo, fqdn, sender,
                            result, recipient, subaddress, tokenSet,
                            "INVALID", "SPF_TLD"
                    );
                    Long timeKey = (Long) resultSet[0];
                    timeKeySet.add(timeKey);
                    if (Reputation.isUndesirable(ip, fqdn, helo, sender, result, user, recipient)) {
                        String block = Block.keyBlockKey(
                                client, user, ip, helo, sender,
                                fqdn, result, null
                        );
                        if (Block.addExact(block)) {
                            Server.logDebug(timeKey, "new BLOCK '" + block + "' added by 'RESERVED'.");
                        }
                    }
                    Reputation.addUnacceptable(client, user, ip, fqdn, helo, sender, result, recipient);
                    return "action=554 5.7.1 SPFBL "
                            + sender + " has a reserved domain. "
                            + "See http://spfbl.net/en/feedback\n\n";
                } else if (recipient != null && !isValidRecipient(recipient)) {
                    Object[] resultSet = SPF.getTicket(
                            clientIP, client, user, ip, helo, fqdn, sender,
                            result, recipient, subaddress, tokenSet,
                            "INEXISTENT", "RECIPIENT_INVALID"
                    );
                    Long timeKey = (Long) resultSet[0];
                    timeKeySet.add(timeKey);
                    Reputation.addUnacceptable(client, user, ip, fqdn, helo, sender, result, recipient);
                    return "action=550 5.1.1 SPFBL the account "
                            + "that you tried to reach does not exist. "
                            + "See http://spfbl.net/en/feedback\n\n";
                } else if (sender != null && !result.equals("PASS") && fqdn == null) {
                    boolean hasActionHOLD = client == null ? false : client.hasActionHOLD();
                    boolean usingHeader = user == null ? false : user.usingHeader();
                    if (hasActionHOLD && usingHeader) {
                        String url = Core.getURL(user);
                        String ticket = SPF.getPostfixTicketHOLD(
                                clientIP, client, user, ip, helo, fqdn, sender,
                                result, recipient, subaddress, instance, tokenSet,
                                "ENVELOPE_INVALID;NOTPASS"
                        );
                        return "action=PREPEND Received-SPFBL: HOLD "
                                + (url == null ? ticket : url + ticket) + "\n\n";
                    } else if (spf != null && spf.isTemporary()) {
                        long timeKey = SPF.addQuery(
                                clientIP, client, user, ip, helo, fqdn, sender,
                                result, recipient, subaddress, tokenSet,
                                "GREYLIST", "SPF_TEMP_ERROR"
                        );
                        timeKeySet.add(timeKey);
                        return "action=451 4.7.1 SPFBL you are greylisted. "
                                + "See http://spfbl.net/en/feedback\n\n";
                    } else {
                        Object[] resultSet = SPF.addQuerySpam(
                                clientIP, client, user, ip, helo, fqdn, sender,
                                result, recipient, subaddress, tokenSet,
                                "INVALID", "ENVELOPE_INVALID;NOTPASS"
                        );
                        Long timeKey = (Long) resultSet[0];
                        timeKeySet.add(timeKey);
                        if (Reputation.isUndesirable(ip, fqdn, helo, sender, result, user, recipient)) {
                            Block.addBlockKey(
                                    timeKey, client, user, ip, helo, sender,
                                    fqdn, result, null, "INVALID"
                            );
                        }
                        Reputation.addUnacceptable(client, user, ip, fqdn, helo, sender, result, recipient);
                        return "action=554 5.7.1 SPFBL invalid hostname. "
                                + "See http://spfbl.net/en/feedback\n\n";
                    }
                } else if (recipientTrapTime != null) {
                    Reputation.addUnacceptable(client, user, ip, fqdn, helo, sender, result, recipient);
                    if (System.currentTimeMillis() > recipientTrapTime) {
                        // Spamtrap.
                        Object[] resultSet = SPF.getTicket(
                                clientIP, client, user, ip, helo, fqdn, sender,
                                result, recipient, subaddress, tokenSet,
                                "TRAP", "RECIPIENT_TRAP"
                        );
                        Long timeKey = (Long) resultSet[0];
                        timeKeySet.add(timeKey);
                        if (Math.random() > 0.8d) {
                            Block.addBlockKey(
                                    timeKey, client, user, ip, helo, sender,
                                    fqdn, result, null, recipient + ";SPAMTRAP"
                            );
                        }
                        return "action=DISCARD SPFBL discarded by spamtrap.\n\n";
                    } else {
                        // Inexistent.
                        Object[] resultSet = SPF.getTicket(
                                clientIP, client, user, ip, helo, fqdn, sender,
                                result, recipient, subaddress, tokenSet,
                                "INEXISTENT", "RECIPIENT_INEXISTENT"
                        );
                        Long timeKey = (Long) resultSet[0];
                        timeKeySet.add(timeKey);
                        return "action=550 5.1.1 SPFBL the account "
                                + "that you tried to reach does not exist. "
                                + "See http://spfbl.net/en/feedback\n\n";
                    }
                } else if (recipient != null && recipient.startsWith("postmaster@")) {
                    String url = Core.getURL(user);
                    Object[] resultSet = SPF.getTicket(
                            clientIP, client, user, ip, helo, fqdn, sender,
                            result, recipient, subaddress, tokenSet,
                            "ACCEPT", "RECIPIENT_POSTMASTER"
                    );
                    Long timeKey = (Long) resultSet[0];
                    timeKeySet.add(timeKey);
                    String ticket = (String) resultSet[1];
                    if (user != null && !user.usingHeader()) {
                        Reputation.addAcceptable(client, user, ip, fqdn, helo, sender, result, recipient);
                    }
                    return "action=PREPEND "
                            + "Received-SPFBL: " + result + " "
                            + (url == null ? ticket : url + URLEncoder.encode(ticket, "UTF-8")) + "\n\n";
                } else if (usingSince < 7 && Abuse.isBlocked(client, user, ip, fqdn, sender, result)) {
                    if (user != null && user.usingHeader()) {
                        long timeKey = SPF.addQuery(
                                clientIP, client, user, ip, helo, fqdn, sender,
                                result, recipient, subaddress, tokenSet,
                                "FLAG", "ABUSE_BLOCKED"
                        );
                        timeKeySet.add(timeKey);
                        String url = Core.getURL(user);
                        String ticket = SPF.createTicket(timeKey, tokenSet);
                        return "action=PREPEND Received-SPFBL: FLAG "
                                + (url == null ? ticket : url + ticket) + "\n\n";
                    } else {
                        Action action = client == null ? Action.FLAG : client.getActionRED();
                        if (action == Action.REJECT) {
                            Object[] resultSet = SPF.addQuerySpam(
                                    clientIP, client, user, ip, helo, fqdn, sender,
                                    result, recipient, subaddress, tokenSet,
                                    "REJECT", "ABUSE_BLOCKED"
                            );
                            Long timeKey = (Long) resultSet[0];
                            User.Query queryLocal = (User.Query) resultSet[1];
                            if (queryLocal == null) {
                                Abuse.reportAbuse(
                                        timeKey, clientIP, client, user,
                                        sender, recipient,
                                        ip, fqdn, result, null
                                );
                            } else {
                                Abuse.offer(timeKey, queryLocal);
                            }
                            timeKeySet.add(timeKey);
                            Block.addBlockKey(
                                    timeKey, client, user, ip, helo, sender,
                                    fqdn, result, null, "ABUSE_BLOCKED"
                            );
                            Reputation.addUndesirable(
                                    client, user, ip, fqdn,
                                    helo, sender, result, recipient
                            );
                            String url = Core.getUnblockURL(
                                    client, user, ip,
                                    sender, fqdn, recipient
                            );
                            if (url == null) {
                                return "action=554 5.7.1 SPFBL "
                                        + "you are temporarily listed. "
                                        + "See http://spfbl.net/en/feedback\n\n";
                            } else {
                                return "action=554 5.7.1 SPFBL "
                                    + "BLOCKED " + url + "\n\n";
                            }
                        } else if (action == Action.DEFER) {
                            if (Defer.defer(fluxo, Core.getDeferTimeRED())) {
                                String url = Core.getReleaseURL(user, fluxo);
                                SPF.addQuery(
                                        clientIP, client, user, ip, helo, fqdn, sender,
                                        result, recipient, subaddress, tokenSet,
                                        "LISTED", "ABUSE_BLOCKED"
                                );
                                if (url == null || Defer.count(fluxo) > 1) {
                                    return "action=451 4.7.2 SPFBL "
                                            + "you are temporarily listed. "
                                            + "See http://spfbl.net/en/feedback\n\n";
                                } else if (result.equals("PASS") && enviarLiberacao(url, sender, recipient)) {
                                    return "action=451 4.7.2 SPFBL "
                                            + "you are temporarily listed. "
                                            + "See http://spfbl.net/en/feedback\n\n";
                                } else {
                                    return "action=451 4.7.2 SPFBL LISTED " + url + "\n\n";
                                }
                            } else {
                                Object[] resultSet = SPF.addQuerySpam(
                                        clientIP, client, user, ip, helo, fqdn, sender,
                                        result, recipient, subaddress, tokenSet,
                                        "REJECT", "ABUSE_BLOCKED"
                                );
                                Long timeKey = (Long) resultSet[0];
                                timeKeySet.add(timeKey);
                                Reputation.addUnacceptable(client, user, ip, fqdn, helo, sender, result, recipient);
                                return "action=554 5.7.1 SPFBL too many retries. "
                                        + "See http://spfbl.net/en/feedback\n\n";
                            }
                        } else if (action == Action.FLAG) {
                            String url = Core.getURL(user);
                            String ticket = SPF.getPostfixTicketFLAG(
                                    clientIP, client, user, ip, helo, fqdn, sender,
                                    result, recipient, subaddress, instance, tokenSet,
                                    "ABUSE_BLOCKED"
                            );
                            return "action=PREPEND Received-SPFBL: FLAG "
                                    + (url == null ? ticket : url + ticket) + "\n\n";
                        } else if (action == Action.HOLD) {
                            String url = Core.getURL(user);
                            String ticket = SPF.getPostfixTicketHOLD(
                                    clientIP, client, user, ip, helo, fqdn, sender,
                                    result, recipient, subaddress, instance, tokenSet,
                                    "ABUSE_BLOCKED"
                            );
                            return "action=PREPEND Received-SPFBL: HOLD "
                                    + (url == null ? ticket : url + ticket) + "\n\n";
                        } else {
                            SPF.addQuery(
                                    clientIP, client, user, ip, helo, fqdn, sender,
                                    result, recipient, subaddress, tokenSet,
                                    "FLAG", "ABUSE_BLOCKED"
                            );
                            return "action=WARN undefined action.\n\n";
                        }
                    }
                } else if ((envelopeFlag = Reputation.getEnvelopeFlag(ip, fqdn, helo, sender, result, user, recipient)) == HARMFUL || envelopeFlag == UNDESIRABLE) {
                    if (user != null && user.usingHeader()) {
                        long time = SPF.addQuery(
                                clientIP, client, user, ip, helo, fqdn, sender,
                                result, recipient, subaddress, tokenSet,
                                "FLAG", null
                        );
                        String url = Core.getURL(user);
                        String ticket = SPF.createTicket(time, tokenSet);
                        return "action=PREPEND Received-SPFBL: FLAG "
                                + (url == null ? ticket : url + ticket) + "\n\n";
                    } else {
                        Action action = client == null ? Action.FLAG : client.getActionRED();
                        if (action == Action.REJECT) {
                            Object[] resultSet = SPF.addQuerySpam(
                                    clientIP, client, user, ip, helo, fqdn, sender,
                                    result, recipient, subaddress, tokenSet,
                                    "REJECT", "ENVELOPE_" + envelopeFlag
                            );
                            Long timeKey = (Long) resultSet[0];
                            User.Query queryLocal = (User.Query) resultSet[1];
                            if (queryLocal == null) {
                                Abuse.reportAbuse(
                                        timeKey, clientIP, client, user,
                                        sender, recipient,
                                        ip, fqdn, result, null
                                );
                            } else {
                                Abuse.offer(timeKey, queryLocal);
                            }
                            timeKeySet.add(timeKey);
                            Reputation.addUnacceptable(
                                    client, user, ip, fqdn,
                                    helo, sender, result, recipient
                            );
                            String url = Core.getUnblockURL(
                                    client, user, ip,
                                    sender, fqdn, recipient
                            );
                            if (url == null) {
                                return "action=554 5.7.1 SPFBL "
                                        + "you are temporarily listed. "
                                        + "See http://spfbl.net/en/feedback\n\n";
                            } else {
                                return "action=554 5.7.1 SPFBL "
                                    + "BLOCKED " + url + "\n\n";
                            }
                        } else if (action == Action.DEFER) {
                            if (Defer.defer(fluxo, Core.getDeferTimeRED())) {
                                String url = Core.getReleaseURL(user, fluxo);
                                SPF.addQuery(
                                        clientIP, client, user, ip, helo, fqdn, sender,
                                        result, recipient, subaddress, tokenSet,
                                        "LISTED", "ENVELOPE_" + envelopeFlag
                                );
                                if (url == null || Defer.count(fluxo) > 1) {
                                    return "action=451 4.7.2 SPFBL "
                                            + "you are temporarily listed. "
                                            + "See http://spfbl.net/en/feedback\n\n";
                                } else if (result.equals("PASS") && enviarLiberacao(url, sender, recipient)) {
                                    return "action=451 4.7.2 SPFBL "
                                            + "you are temporarily listed. "
                                            + "See http://spfbl.net/en/feedback\n\n";
                                } else {
                                    return "action=451 4.7.2 SPFBL LISTED " + url + "\n\n";
                                }
                            } else {
                                Object[] resultSet = SPF.addQuerySpam(
                                        clientIP, client, user, ip, helo, fqdn, sender,
                                        result, recipient, subaddress, tokenSet,
                                        "REJECT", "ENVELOPE_" + envelopeFlag
                                );
                                Long timeKey = (Long) resultSet[0];
                                timeKeySet.add(timeKey);
                                Reputation.addUnacceptable(client, user, ip, fqdn, helo, sender, result, recipient);
                                return "action=554 5.7.1 SPFBL too many retries. "
                                        + "See http://spfbl.net/en/feedback\n\n";
                            }
                        } else if (action == Action.FLAG) {
                            String url = Core.getURL(user);
                            String ticket = SPF.getPostfixTicketFLAG(
                                    clientIP, client, user, ip, helo, fqdn, sender,
                                    result, recipient, subaddress, instance, tokenSet,
                                    "ENVELOPE_" + envelopeFlag
                            );
                            return "action=PREPEND Received-SPFBL: FLAG "
                                    + (url == null ? ticket : url + ticket) + "\n\n";
                        } else if (action == Action.HOLD) {
                            String url = Core.getURL(user);
                            String ticket = SPF.getPostfixTicketHOLD(
                                    clientIP, client, user, ip, helo, fqdn, sender,
                                    result, recipient, subaddress, instance, tokenSet,
                                    "ENVELOPE_" + envelopeFlag
                            );
                            return "action=PREPEND Received-SPFBL: HOLD "
                                    + (url == null ? ticket : url + ticket) + "\n\n";
                        } else {
                            SPF.addQuery(
                                    clientIP, client, user, ip, helo, fqdn, sender,
                                    result, recipient, subaddress, tokenSet,
                                    "FLAG", "ENVELOPE_" + envelopeFlag
                            );
                            return "action=WARN undefined action.\n\n";
                        }
                    }
                } else if (result.equals("PASS") && Reputation.isDesirable(ip, fqdn, helo, sender, result)) {
                    String url = Core.getURL(user);
                    Object[] resultSet = SPF.addQueryHam(
                            clientIP, client, user, ip, helo, fqdn, sender,
                            result, recipient, subaddress, tokenSet,
                            "ACCEPT", null
                    );
                    Long timeKey = (Long) resultSet[0];
                    timeKeySet.add(timeKey);
                    String ticket = (String) resultSet[1];
                    if (user != null && !user.usingHeader()) {
                        Reputation.addAcceptable(client, user, ip, fqdn, helo, sender, result, recipient);
                    }
                    return "action=PREPEND "
                            + "Received-SPFBL: PASS "
                            + (url == null ? ticket : url + URLEncoder.encode(ticket, "UTF-8")) + "\n\n";
                } else if (Provider.containsFQDN(fqdn)) {
                    String url = Core.getURL(user);
                    Object[] resultSet = SPF.addQueryHam(
                            clientIP, client, user, ip, helo, fqdn, sender,
                            result, recipient, subaddress, tokenSet,
                            "ACCEPT", null
                    );
                    Long timeKey = (Long) resultSet[0];
                    timeKeySet.add(timeKey);
                    String ticket = (String) resultSet[1];
                    if (user != null && !user.usingHeader()) {
                        Reputation.addAcceptable(client, user, ip, fqdn, helo, sender, result, recipient);
                    }
                    return "action=PREPEND "
                            + "Received-SPFBL: " + result + " "
                            + (url == null ? ticket : url + URLEncoder.encode(ticket, "UTF-8")) + "\n\n";
                } else if ((result.equals("SOFTFAIL") || usingSince < 7) && Defer.defer(fluxo, Core.getDeferTimeSOFTFAIL())) {
                    long timeKey;
                    if (result.equals("SOFTFAIL")) {
                        timeKey = SPF.addQuery(
                                clientIP, client, user, ip, helo, fqdn, sender,
                                result, recipient, subaddress, tokenSet,
                                "GREYLIST", "SPF_SOFTFAIL"
                        );
                    } else {
                        timeKey = SPF.addQuery(
                                clientIP, client, user, ip, helo, fqdn, sender,
                                result, recipient, subaddress, tokenSet,
                                "GREYLIST", "DOMAIN_EMERGED;" + usingSince
                        );
                    }
                    timeKeySet.add(timeKey);
                    return "action=451 4.7.1 SPFBL you are greylisted. "
                            + "See http://spfbl.net/en/feedback\n\n";
                } else {
                    String url = Core.getURL(user);
                    Object[] resultSet = SPF.addQueryHam(
                            clientIP, client, user, ip, helo, fqdn, sender,
                            result, recipient, subaddress, tokenSet,
                            "ACCEPT", null
                    );
                    Long timeKey = (Long) resultSet[0];
                    timeKeySet.add(timeKey);
                    String ticket = (String) resultSet[1];
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
    
    private static int usingSince(String... list) {
        Integer since = net.spfbl.data.Domain.usingSinceNewest(list);
        if (since == null) {
            return -1;
        } else {
            return since;
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
                    if (token.startsWith(">") && isValidEmail(token.substring(1))) {
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
            byte[] byteArray = Server.decryptToByteArrayURLSafe(ticket);
            if (byteArray == null) {
                return null;
            } else if (byteArray.length > 8) {
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
                            if (isValidEmail(token)) {
                                return token;
                            }
                        }
                    }
                    return null;
                }
            } else {
                return null;
            }
        }
    }
    
    public static String getClientURLSafe(String ticket) {
        if (ticket == null) {
            return null;
        } else {
            byte[] byteArray = Server.decryptToByteArrayURLSafe(ticket);
            if (byteArray == null) {
                return null;
            } else if (byteArray.length > 8) {
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
                            if (isValidEmail(token)) {
                                return token;
                            }
                        }
                    }
                    return null;
                }
            } else {
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
                        if (isValidEmail(token)) {
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
                    if (token.startsWith("@") && isHostname(token.substring(1))) {
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
        } else if (isValidIP(token)) {
            return !Subnet.isReservedIP(token);
        } else if (token.startsWith(".") && isHostname(token.substring(1))) {
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
    public static String processSPF(
            InetAddress clientIP,
            Client client,
            User user,
            String query,
            LinkedList<User> userList,
            TreeSet<Long> timeKeySet
    ) {
        try {
            String result;
            if (query.length() == 0) {
                return "INVALID QUERY\n";
            } else {
                String origin;
                if (client == null) {
                    origin = clientIP.getHostAddress();
                } else if (client.hasEmail()) {
                    origin = clientIP.getHostAddress() + " " + client.getDomain() + " " + client.getEmail();
                } else {
                    origin = clientIP.getHostAddress() + " " + client.getDomain();
                }
                StringTokenizer tokenizer = new StringTokenizer(query, " ");
                String firstToken = tokenizer.nextToken();
                if (firstToken.equals("SPAM") && tokenizer.countTokens() == 1) {
                    String ticket = tokenizer.nextToken();
                    int index = ticket.lastIndexOf("/") + 1;
                    ticket = ticket.substring(index);
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
                } else if (firstToken.equals("BAN") && tokenizer.countTokens() == 1) {
                    String token = tokenizer.nextToken();
                    if (client == null) {
                        result = "CLIENT NOT DEFINED\n";
                    } else if (isValidIP(token)) {
                        String ip = Subnet.normalizeIP(token);
                        if (Client.ban(client, ip)) {
                            result = "BANNED " + ip + "\n";
                        } else {
                            result = "NOT BANNED\n";
                        }
                    } else if (isValidCIDR(token)) {
                        String cidr = Subnet.normalizeCIDR(token);
                        if (Client.ban(client, cidr)) {
                            result = "BANNED " + cidr + "\n";
                        } else {
                            result = "NOT BANNED\n";
                        }
                    } else {
                        result = "INVALID COMMAND\n";
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
                    } else if (isValidIP(token) && tokenizer.countTokens() == 0) {
                        if (SPF.addComplainSafe(token)) {
                            Client.ban(client, token);
                            Abuse.addHarmful(token, FQDN.getFQDN(token, true));
                            CIDR.addHarmful(token);
                            result = "COMPLAINED " + Subnet.normalizeIP(token) + "\n";
                        } else {
                            result = "NOT COMPLAINED\n";
                        }
                    } else if (token.startsWith("Subject:")) {
                        String key = "Subject";
                        int index = token.indexOf(':');
                        String subject = token.substring(index+1);
                        String from = null;
                        while (tokenizer.hasMoreTokens()) {
                            token = tokenizer.nextToken();
                            if (token.startsWith("From:")) {
                                key = "From";
                                index = token.indexOf(':');
                                from = token.substring(index+1);
                            } else if (key.equals("From")) {
                                from += ' ' + token;
                            } else if (key.equals("Subject")) {
                                subject += ' ' + token;
                            }
                        }
                        if (from == null) {
                            result = "INVALID COMMAND\n";
                        } else if (subject == null) {
                            result = "INVALID COMMAND\n";
                        } else {
                            User recipientUser = User.get(from);
                            if (recipientUser == null) {
                                // Se a consulta originar de destinatário com postmaster cadastrado,
                                // considerar o próprio postmaster como usuário da consulta.
                                index = from.indexOf('@');
                                String postmaster = "postmaster" + from.substring(index);
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
                                result = user.blockBySubject(subject) + '\n';
                            }
                        }
                    } else {
                        result = "INVALID COMMAND\n";
                    }
                } else if (firstToken.equals("HOLDING") && tokenizer.countTokens() == 1) {
                    String ticket = tokenizer.nextToken();
                    int index = ticket.lastIndexOf("/") + 1;
                    ticket = ticket.substring(index);
                    result = getHoldStatus(client, ticket, userList) + '\n';
                } else if (firstToken.equals("LINK") && tokenizer.hasMoreTokens()) {
                    String ticketSet = tokenizer.nextToken();
                    TreeSet<String> linkSet = new TreeSet<>();
                    while (tokenizer.hasMoreTokens()) {
                        linkSet.add(tokenizer.nextToken());
                    }
                    StringTokenizer tokenizerTicket = new StringTokenizer(ticketSet, ";");
                    boolean hold = false;
                    boolean flag = false;
                    boolean reject = false;
                    boolean found = false;
                    TreeMap<Long,Query> queryMap = new TreeMap<>();
                    while (tokenizerTicket.hasMoreTokens()) {
                        String ticket = tokenizerTicket.nextToken();
                        int index = ticket.lastIndexOf("/") + 1;
                        ticket = ticket.substring(index);
                        String userEmail;
                        try {
                            userEmail = SPF.getClientURLSafe(ticket);
                        } catch (Exception ex) {
                            userEmail = client == null ? null : client.getEmail();
                        }
                        if ((user = User.get(userEmail)) != null) {
                            userList.add(user);
                            long dateTicket = SPF.getDateTicket(ticket);
                            Query queryTicket = user.getQuery(dateTicket);
                            if (queryTicket != null) {
                                queryMap.put(dateTicket, queryTicket);
                                timeKeySet.add(dateTicket);
                                found = true;
                                String filter = null;
                                Action actionQuery = null;
                                queryTicket.setLinkSet(dateTicket, linkSet);
                                String resultLocal;
                                if (queryTicket.hasMalwareNotIgnored()) {
                                    actionQuery = client == null ? Action.REJECT : client.getActionBLOCK();
                                    filter = "MALWARE_NOT_IGNORED;" + queryTicket.getMalware();
                                    queryTicket.banOrBlockForAdmin(dateTicket, filter);
                                    queryTicket.banOrBlock(dateTicket, filter);
                                } else if (queryTicket.hasExecutableNotIgnored()) {
                                    if (queryTicket.hasExecutableBlocked()) {
                                        actionQuery = client == null ? Action.REJECT : client.getActionBLOCK();
                                        filter = "EXECUTABLE_BLOCKED";
                                        queryTicket.banOrBlockForAdmin(dateTicket, filter);
                                        queryTicket.banOrBlock(dateTicket, filter);
                                    } else if (queryTicket.isUndesirable()) {
                                        actionQuery = client == null ? Action.REJECT : client.getActionBLOCK();
                                        filter = "EXECUTABLE_UNDESIRABLE";
                                        queryTicket.banOrBlockForAdmin(dateTicket, filter);
                                        queryTicket.banOrBlock(dateTicket, filter);
                                    } else {
                                        actionQuery = client == null ? Action.FLAG : client.getActionRED();
                                        filter = "EXECUTABLE_NOT_IGNORED";
                                    }
                                } else if ((resultLocal = queryTicket.getAnyLinkSuspect(false)) != null) {
                                    if (queryTicket.isUndesirable()) {
                                        actionQuery = client == null ? Action.REJECT : client.getActionBLOCK();
                                        filter = "HREF_UNDESIRABLE;" + resultLocal;
                                    } else {
                                        actionQuery = client == null ? Action.FLAG : client.getActionRED();
                                        filter = "HREF_SUSPECT;" + resultLocal;
                                    }
                                }
                                if (queryTicket.isHolding()) {
                                    hold = true;
                                }
                                if (actionQuery != null) {
                                    switch (actionQuery) {
                                        case REJECT:
                                            reject = true;
                                            break;
                                        case HOLD:
                                            hold = true;
                                            break;
                                        case FLAG:
                                            flag = true;
                                            break;
                                    }
                                }
                                if (filter != null) {
                                    queryTicket.setFilter(filter);
                                    Server.logDebug(dateTicket, "FILTER " + filter);
                                }
                            }
                        }
                    }
                    if (reject) {
                        for (long timeKey : queryMap.keySet()) {
                            Query queryTicket = queryMap.get(timeKey);
                            queryTicket.setResult("REJECT");
                            queryTicket.addHarmful(timeKey);
                            User.storeDB(timeKey, queryTicket);
                            Abuse.offer(timeKey, queryTicket);
                        }
                        result = "REJECT\n";
                    } else if (hold) {
                        for (long timeKey : queryMap.keySet()) {
                            Query queryTicket = queryMap.get(timeKey);
                            queryTicket.setResult("HOLD");
                            User.storeDB(timeKey, queryTicket);
                        }
                        result = "HOLD\n";
                    } else if (flag) {
                        for (long timeKey : queryMap.keySet()) {
                            Query queryTicket = queryMap.get(timeKey);
                            queryTicket.setResult("FLAG");
                            User.storeDB(timeKey, queryTicket);
                        }
                        result = "FLAG\n";
                    } else if (found) {
                        for (long timeKey : queryMap.keySet()) {
                            Query queryTicket = queryMap.get(timeKey);
                            User.storeDB(timeKey, queryTicket);
                        }
                        result = "CLEAR\n";
                    } else {
                        for (long timeKey : queryMap.keySet()) {
                            Query queryTicket = queryMap.get(timeKey);
                            User.storeDB(timeKey, queryTicket);
                        }
                        result = "NOT FOUND\n";
                    }
                } else if (firstToken.equals("SIGNER") && tokenizer.hasMoreTokens()) {
                    String ticketSet = tokenizer.nextToken();
                    TreeSet<String> signerSet = new TreeSet<>();
                    while (tokenizer.hasMoreTokens()) {
                        signerSet.add(tokenizer.nextToken());
                    }
                    result = "NOT FOUND\n";
                    StringTokenizer tokenizerTicket = new StringTokenizer(ticketSet, ";");
                    while (tokenizerTicket.hasMoreTokens()) {
                        String ticket = tokenizerTicket.nextToken();
                        int index = ticket.lastIndexOf("/") + 1;
                        ticket = ticket.substring(index);
                        String userEmail;
                        try {
                            userEmail = SPF.getClientURLSafe(ticket);
                        } catch (Exception ex) {
                            userEmail = client == null ? null : client.getEmail();
                        }
                        if ((user = User.get(userEmail)) != null) {
                            userList.add(user);
                            long dateTicket = SPF.getDateTicket(ticket);
                            timeKeySet.add(dateTicket);
                            User.Query queryTicket = user.getQuery(dateTicket);
                            if (queryTicket != null) {
                                if (queryTicket.setSignerSet(signerSet)) {
                                    result = "ADDED\n";
                                }
                            }
                        }
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
                        int index = ticket.lastIndexOf("/") + 1;
                        ticket = ticket.substring(index);
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
                                long timeKey = getDateTicket(ticket);
                                timeKeySet.add(timeKey);
                                User.Query userQuery = user.getQuery(timeKey);
                                String resultMalware;
                                if (userQuery != null && (resultMalware = userQuery.setMalware(timeKey, nameBuilder.toString())) != null) {
                                    User.storeDB(timeKey, userQuery);
                                    if (resultMalware.equals("ACCEPT")) {
                                        accept = true;
                                    } else if (userQuery.isWhiteKey()) {
                                        userQuery.addUndesirable(timeKey);
                                    } else {
                                        userQuery.banOrBlock(timeKey, "MALWARE");
                                        userQuery.addHarmful(timeKey);
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
                                resultBuilder.append("OK ");
                                resultBuilder.append(tokenSet);
                                resultBuilder.append(recipient == null ? "" : " >" + recipient);
                            }
                            resultBuilder.append("\n");
                        }
                    }
                    result = resultBuilder.toString();
                } else if (firstToken.equals("BODY") && tokenizer.countTokens() > 1) {
                    String ticketSet = tokenizer.nextToken();
                    byte[] data = Core.BASE64STANDARD.decode(tokenizer.nextToken());
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
                                timeKeySet.add(timeTicket);
                                Query queryTicket = entry.getValue();
                                queryMap.put(timeTicket, queryTicket);
                            }
                        }
                        if (queryMap.isEmpty()) {
                            result = "NOT FOUND\n";
                        } else {
                            String charset = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : "UTF-8";
                            for (long time : queryMap.keySet()) {
                                timeKeySet.add(time);
                                Query queryTicket = queryMap.get(time);
                                queryTicket.setBody(data, charset);
                                if ((result = queryTicket.getBodySuspect()) != null) {
                                    queryTicket.setFilter("BODY_SUSPECT;" + result);
                                }
                                User.storeDB(time, queryTicket);
                            }
                            result = "CHANGED\n";
                        }
                    }
                } else if (firstToken.equals("MESSAGE") && tokenizer.countTokens() == 2) {
                    String queueID = tokenizer.nextToken();
                    String encoded = tokenizer.nextToken();
                    String fqdn = FQDN.getFQDN(clientIP, false);
                    if (fqdn == null && client != null) {
                        fqdn = client.getDomain();
                    }
                    if (ServerSMTP.storeIncomingMessage(queueID, fqdn, encoded)) {
                        result = "STORED\n";
                    } else {
                        result = "NOT STORED\n";
                    }
                } else if (firstToken.equals("HEADER") && tokenizer.hasMoreTokens()) {
                    String ticketSet = tokenizer.nextToken();
                    String key = null;
                    String from = null;
                    String replyto = null;
                    String messageID = null;
                    String inReplyTo = null;
                    String queueID = null;
                    String unsubscribe = null;
                    String subject = null;
                    String date = null;
                    TreeSet<String> linkSet = new TreeSet<>();
                    TreeSet<String> signerSet = null;
                    while (tokenizer.hasMoreTokens()) {
                        String token = tokenizer.nextToken();
                        if (from == null && token.startsWith("From:")) {
                            key = "From";
                            int index = token.indexOf(':');
                            from = token.substring(index+1);
                        } else if (replyto == null && token.startsWith("ReplyTo:") || token.startsWith("Reply-To:")) {
                            key = "Reply-To";
                            int index = token.indexOf(':');
                            replyto = token.substring(index+1);
                        } else if (messageID == null && token.startsWith("Message-ID:")) {
                            key = "Message-ID";
                            int index = token.indexOf(':');
                            messageID = token.substring(index+1);
                        } else if (inReplyTo == null && token.startsWith("In-Reply-To:")) {
                            key = "In-Reply-To";
                            int index = token.indexOf(':');
                            inReplyTo = token.substring(index+1);
                        } else if (queueID == null && token.startsWith("Queue-ID:")) {
                            key = "Queue-ID";
                            int index = token.indexOf(':');
                            queueID = token.substring(index+1);
                        } else if (unsubscribe == null && token.startsWith("List-Unsubscribe:")) {
                            key = "List-Unsubscribe";
                            int index = token.indexOf(':');
                            unsubscribe = token.substring(index+1);
                        } else if (subject == null && token.startsWith("Subject:")) {
                            key = "Subject";
                            int index = token.indexOf(':');
                            subject = token.substring(index+1);
                        } else if (date == null && token.startsWith("Date:")) {
                            key = "Date";
                            int index = token.indexOf(':');
                            date = token.substring(index+1);
                        } else if (signerSet == null && token.startsWith("DKIM:")) {
                            key = "DKIM";
                            int index = token.indexOf(':');
                            token = token.substring(index+1);
                            signerSet = Core.getTreeSet(token, ",");
                        } else if (key == null) {
                            linkSet.add(token);
                        } else if (key.equals("From")) {
                            from += ' ' + token;
                        } else if (key.equals("Reply-To")) {
                            replyto += ' ' + token;
                        } else if (key.equals("Message-ID")) {
                            messageID += ' ' + token;
                        } else if (key.equals("In-Reply-To")) {
                            inReplyTo += ' ' + token;
                        } else if (key.equals("Queue-ID")) {
                            queueID += ' ' + token;
                        } else if (key.equals("List-Unsubscribe")) {
                            unsubscribe += ' ' + token;
                        } else if (key.equals("Subject")) {
                            subject += ' ' + token;
                        } else if (key.equals("Date")) {
                            date += ' ' + token;
                        } else if (signerSet != null && key.equals("DKIM")) {
                            signerSet.addAll(Core.getTreeSet(token, ","));
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
                        boolean found = false;
                        if ((subject = Core.tryToDecodeRecursivelyMIME(subject)) != null) {
                            subject = subject.replaceAll("[\\s\\r\\n\\t]+", " ");
                            subject = Dictionary.normalizeCharacters(subject);
                        }
                        if (Dictionary.getFlagREGEX(subject) == HARMFUL) {
                            String regex = Dictionary.getREGEX(subject);
                            if (regex != null && regex.startsWith("^") && regex.endsWith("$")) {
                                String hashString = String.format("%08X", regex.hashCode());
                                linkSet.add("MALWARE=SPFBL.Subject." + hashString);
                            }
                        }
                        TreeSet<String> unblockURLSet = new TreeSet<>();
                        StringTokenizer ticketTokenizer = new StringTokenizer(ticketSet, ";");
                        TreeMap<Long,User.Query> queryMap = new TreeMap<>();
                        while (ticketTokenizer.hasMoreTokens()) {
                            String ticket = ticketTokenizer.nextToken();
                            int index = ticket.lastIndexOf("/") + 1;
                            ticket = ticket.substring(index);
                            String userEmail;
                            try {
                                userEmail = SPF.getClientURLSafe(ticket);
                            } catch (Exception ex) {
                                userEmail = client == null ? null : client.getEmail();
                            }
                            if ((user = User.get(userEmail)) != null) {
                                userList.add(user);
                                long dateTicket = SPF.getDateTicket(ticket);
                                timeKeySet.add(dateTicket);
                                User.Query queryTicket = user.getQuery(dateTicket);
                                if (queryTicket != null) {
                                    found = true;
                                    queryMap.put(dateTicket, queryTicket);
                                    Action actionRED = client == null ? Action.FLAG : client.getActionRED();
                                    Action actionBLOCK = client == null ? Action.REJECT : client.getActionBLOCK();
                                    queryTicket.setSignerSet(signerSet);
                                    queryTicket.setLinkSet(dateTicket, linkSet);
                                    String resultLocal = queryTicket.setHeader(
                                            dateTicket, client,
                                            from, replyto, subject,
                                            messageID, inReplyTo,
                                            queueID, date, unsubscribe,
                                            actionBLOCK, actionRED
                                    );
                                    if ("WHITE".equals(resultLocal)) {
                                        whitelisted = true;
                                    } else if ("FLAG".equals(resultLocal)) {
                                        flag = true;
                                    } else if ("HOLD".equals(resultLocal)) {
                                        hold = true;
                                    } else if ("BLOCK".equals(resultLocal)) {
                                        blocklisted = true;
                                    } else if ("REJECT".equals(resultLocal)) {
                                        reject = true;
                                    }
                                    User.storeDB(dateTicket, queryTicket);
                                    queryTicket.notifyHeader();
                                }
                            }
                        }
                        if (whitelisted) {
                            for (long dateTicket : queryMap.keySet()) {
                                User.Query queryTicket = queryMap.get(dateTicket);
                                queryTicket.setResult("WHITE");
                                User.storeDB(dateTicket, queryTicket);
                            }
                            result = "WHITE\n";
                        } else if (blocklisted) {
                            for (long dateTicket : queryMap.keySet()) {
                                User.Query queryTicket = queryMap.get(dateTicket);
                                queryTicket.setResult("BLOCK");
                                User.storeDB(dateTicket, queryTicket);
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
                        } else if (found) {
                            for (long dateTicket : queryMap.keySet()) {
                                User.Query queryTicket = queryMap.get(dateTicket);
                                queryTicket.setResult("ACCEPT");
                                User.storeDB(dateTicket, queryTicket);
                            }
                            result = "CLEAR\n";
                        } else {
                            result = "NOT FOUND\n";
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
                    String ip;
                    String sender;
                    String helo;
                    String recipient;
                    Boolean exists = null;
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
                        exists = Core.getBooleanObject(tokenizer.hasMoreTokens() ? tokenizer.nextToken() : null);
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
                        if (!isHostname(helo)) {
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
                    String subaddress = null;
                    if (recipient != null) {
                        User recipientUser = User.get(recipient);
                        if (recipientUser == null) {
                            // Se a consulta originar de destinatário com postmaster cadastrado,
                            // considerar o próprio postmaster como usuário da consulta.
                            int index = recipient.indexOf('@');
                            if (index > 0) {
                                String postmaster = "postmaster" + recipient.substring(index);
                                User postmasterUser = User.get(postmaster);
                                if (postmasterUser != null) {
                                    user = postmasterUser;
                                }
                            }
                        } else {
                            user = recipientUser;
                        }
                        int index1 = recipient.indexOf('+');
                        int index2 = recipient.lastIndexOf('@');
                        if (index1 > 0 && index2 > 0) {
                            // Subaddress Extension.
                            // https://tools.ietf.org/html/rfc5233.html
                            String part = recipient.substring(0, index1);
                            subaddress = recipient.substring(index1+1, index2);
                            String domain = recipient.substring(index2);
                            recipient = part + domain;
                        }
                    }
                    Long recipientTrapTime;
                    if (exists == null) {
                        recipientTrapTime = Trap.getTimeRecipient(
                                client, user, recipient
                        );
                    } else {
                        Recipient.setExistent(
                                user, recipient, exists
                        );
                        recipientTrapTime = Recipient.getInexistentLong(
                                user, recipient
                        );
                    }
                    ip = SubnetIPv6.tryTransformToIPv4(ip);
                    if (!isValidIP(ip)) {
                        return "INVALID\n";
                    } else if (Subnet.isReservedIP(ip)) {
                        // Message from LAN.
                        if (recipientTrapTime == null) {
                            return "LAN\n";
                        } else {
                            return "INEXISTENT\n";
                        }
                    } else if (sender != null && !Domain.isMailFrom(sender)) {
                        if (client != null && client.isBanActive() && firstToken.equals("CHECK")) {
                            String key = Block.keyBlockKey(
                                    client, user, ip, helo, sender,
                                    null, "NONE", "@"
                            );
                            return "INVALID\nBLOCK registration to ban: " + key + "\n";
                        } else if (Core.isTestingVersion() && clientIP.isLoopbackAddress() && firstToken.equals("CHECK")) {
                            String key = Block.keyBlockKey(
                                    client, user, ip, helo, sender,
                                    null, "NONE", "@"
                            );
                            return "INVALID\nBLOCK registration to ban: " + key + "\n";
                        } else if (Block.isBanned(client, null, ip, helo, null, sender, "NONE", "@")) {
                            Client.ban(client, ip);
                            SPF.addComplainSafe(ip);
                            Abuse.addHarmful(ip, null);
                            CIDR.addHarmful(ip);
                            return "BANNED\n";
                        } else {
                            return "INVALID\n";
                        }
                    } else if (recipient != null && !isValidRecipient(recipient)) {
                        return "INVALID\n";
                    } else if (client != null && client.containsFull(ip)) {
                        // Message from LAN.
                        if (recipientTrapTime == null) {
                            return "LAN\n";
                        } else {
                            return "INEXISTENT\n";
                        }
                    } else {
                        TreeSet<String> tokenSet = new TreeSet<>();
                        if (!Ignore.containsIPorFQDN(ip)) {
                            tokenSet.add(ip);
                        }
                        if (isValidEmail(recipient)) {
                            // Se houver um remetente válido,
                            // Adicionar no ticket para controle.
                            tokenSet.add('>' + recipient);
                        }
                        if (user != null) {
                            userList.add(user);
                            tokenSet.add(user.getEmail() + ':');
                        } else if (client != null && client.hasEmail()) {
                            tokenSet.add(client.getEmail() + ':');
                        }
                        String fqdn;
                        boolean check = firstToken.equals("CHECK");
                        if (!isHostname(helo)) {
                            fqdn = FQDN.getFQDN(ip, check);
                        } else if (Generic.containsGenericFQDN(helo)) {
                            fqdn = FQDN.getFQDN(ip, check);
                        } else if (FQDN.isFQDN(ip, helo)) {
                            fqdn = Domain.normalizeHostname(helo, true);
                        } else if (FQDN.addFQDN(ip, helo, true)) {
                            fqdn = Domain.normalizeHostname(helo, true);
                        } else {
                            fqdn = FQDN.getFQDN(ip, check);
                        }
                        if (fqdn != null) {
                            fqdn = fqdn.toLowerCase();
                            tokenSet.add(fqdn);
                            if (Provider.containsFQDN(fqdn)) {
                                Block.clearFQDN(null, fqdn, Core.getAdminEmail());
                                Block.clearCIDR(null, ip, Core.getAdminEmail());
                            } else if (Ignore.containsFQDN(fqdn)) {
                                Block.clearFQDN(null, fqdn, Core.getAdminEmail());
                                Block.clearCIDR(null, ip, Core.getAdminEmail());
                            }
                        }
                        if (Core.isMyHostname(fqdn)) {
                            String ticket;
                            if (recipientTrapTime != null && recipient != null && !recipient.startsWith("mailer-daemon@")) {
                                return "INEXISTENT\n";
                            } else if (Core.isAdminEmail(sender)) {
                                return "LAN\n";
                            } else if ((ticket = Core.getTicketSender(sender)) != null) {
                                Entry<Long,String> entry = Core.decrypt32(ticket);
                                if (entry == null) {
                                    return "LAN\n";
                                } else if (recipient == null) {
                                    return "LAN\n";
                                } else if (recipient.startsWith("mailer-daemon@")) {
                                    Long timeKey = entry.getKey();
                                    StringTokenizer tokenizer2 = new StringTokenizer(entry.getValue(), " ");
                                    String command = tokenizer2.hasMoreTokens() ? tokenizer2.nextToken() : null;
                                    User userLocal = User.getExact(tokenizer2.hasMoreTokens() ? tokenizer2.nextToken() : null);
                                    Query queryLocal = userLocal == null ? null : userLocal.getQuerySafe(timeKey);
                                    if (timeKey == null) {
                                        return "LAN\n";
                                    } else if (command == null) {
                                        return "LAN\n";
                                    } else if (queryLocal == null) {
                                        return "LAN\n";
                                    } else if (!queryLocal.hasQueueID()) {
                                        return "LAN\n";
                                    } else if (command.equals("release")) {
                                        timeKeySet.add(timeKey);
                                        return "RELEASE " + queryLocal.getQueueID() + " \n";
                                    } else if (command.equals("remove")) {
                                        timeKeySet.add(timeKey);
                                        return "REMOVE " + queryLocal.getQueueID() + " \n";
                                    } else {
                                        return "LAN\n";
                                    }
                                } else {
                                    return "LAN\n";
                                }
                            }
                        }
                        if (White.isDesactive(client, user, ip, fqdn, recipient)) {
                            if (recipientTrapTime == null) {
                                return "LAN\n";
                            } else {
                                return "INEXISTENT\n";
                            }
                        } else if (fqdn == null) {
                            Server.logInfo("no FQDN was found for " + ip + ".");
                        } else if (Domain.isOfficialTLD(fqdn)) {
                            return "INVALID\n";
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
                        } else if (Domain.isOfficialTLD(sender) && !Ignore.contains(sender)) {
                            spf = null;
                            result = "NONE";
                        } else if (Generic.containsGeneric(sender)) {
                            // Don't query SPF from generic domain to avoid high latency.
                            spf = null;
                            result = "NONE";
                        } else if ((spf = CacheSPF.getSafe(sender)) == null) {
                            result = "NONE";
                        } else if (spf.isInexistent()) {
                            result = "SOFTFAIL";
                        } else {
                            result = spf.getResultSafe(ip, sender, helo, logList);
                        }
                        String mx = Domain.extractHost(sender, true);
                        if (recipient != null && result.equals("PASS")) {
                            if (recipient.endsWith(mx)) {
                                // Message from same domain.
                                if (recipientTrapTime == null) {
                                    return "LAN\n";
                                } else {
                                    return "INEXISTENT\n";
                                }
                            } else if (
                                    recipient.equals(Core.getAbuseEmail()) &&
                                    User.exists(sender, "postmaster" + mx)
                                    ) {
                                // Message to abuse.
                                if (recipientTrapTime == null) {
                                    return "LAN\n";
                                } else {
                                    return "INEXISTENT\n";
                                }
                            }
                        }
                        if (result.equals("PASS") || (sender != null && Provider.containsFQDN(fqdn))) {
                            // Quando for PASS, significa que o domínio
                            // autorizou envio pelo IP, portanto o dono dele
                            // é responsavel pelas mensagens.
                            if (!Provider.containsExact(mx)) {
                                // Não é um provedor então
                                // o MX deve ser listado.
                                tokenSet.add(mx);
                                origem = mx;
                            } else if (isValidEmail(sender)) {
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
                                tokenSet.add(Domain.normalizeEmail(sender));
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
                        } else if (fqdn == null) {
                            origem = (sender == null ? "" : sender + '>') + ip;
                            fluxo = origem + ">" + recipient;
                        } else {
                            String dominio = Domain.extractDomainSafe(fqdn, true);
                            origem = (sender == null ? "" : sender + '>') + (dominio == null ? fqdn : dominio.substring(1));
                            fluxo = origem + ">" + recipient;
                        }
                        Flag envelopeFlag;
                        String blockKey;
                        int usingSince =  usingSince(helo, fqdn, sender);
                        if (firstToken.equals("CHECK")) {
                            String results = "\nClient: " + (client == null ? clientIP.getHostAddress() : client);
                            results += "\nUser: " + (user == null ? "NOT DEFINED" : user);
                            String abuse = Abuse.getEmailIP(ip);
                            if (abuse == null) {
                                results += "\n\nAbuse for IP: NOT DEFINED";
                            } else if (Trap.containsAnythingExact(abuse)) {
                                results += "\n\nAbuse for IP: " + abuse + " (inexistent)";
                            } else if (Abuse.isUnsubscribed(abuse)) {
                                results += "\n\nAbuse for IP: " + abuse + " (unsubscribed)";
                            } else {
                                results += "\n\nAbuse for IP: " + abuse;
                            }
                            if (fqdn != null) {
                                if (sender != null && result.equals("PASS") && fqdn.endsWith(".google.com")) {
                                    /**
                                     * GSuite's abuse report rule:
                                     * https://support.google.com/a/answer/178266?hl=en
                                     */
                                    int index = sender.indexOf('@') + 1;
                                    abuse = "abuse@" + sender.substring(index);
                                } else {
                                    abuse = Abuse.getEmailFQDN(fqdn);
                                }
                                if (abuse == null) {
                                    results += "\nAbuse for FQDN: NOT DEFINED";
                                } else if (Trap.containsAnythingExact(abuse)) {
                                    results += "\nAbuse for FQDN: " + abuse + " (inexistent)";
                                } else if (NoReply.isUnsubscribed(abuse)) {
                                    results += "\nAbuse for FQDN: " + abuse + " (unsubscribed)";
                                } else {
                                    results += "\nAbuse for FQDN: " + abuse;
                                }
                            }
                            results += "\n\nSPF resolution results:\n";
                            if (spf == null) {
                                results += "   NONE\n";
                            } else if (spf.isInexistent()) {
                                results += "   NXDOMAIN\n";
                            } else if (logList == null || logList.isEmpty()) {
                                results += "   NONE\n";
                            } else {
                                for (String log : logList) {
                                    results += "   " + log + "\n";
                                }
                            }
                            String white;
                            if ((white = White.find(client, user, ip, sender, fqdn, result, recipient)) != null) {
                                results += "\nFirst WHITE match: " + white + "\n";
                            } else {
                                String block;
                                if ((block = Block.find(client, user, ip, sender, fqdn, result, recipient, true, true, false, false, true, false)) != null) {
                                    results += "\nFirst BLOCK match: " + block + "\n";
                                } else if ((block = Block.findBannedKey((User) null, ip, helo, fqdn, sender, result, null)) != null) {
                                    results += "\nFirst BLOCK match: " + block + "\n";
                                }
                                results += "\nRecommended WHITE key: " + White.key(client, user, ip, sender, fqdn, result) + "\n";
                                String recipientDomain;
                                if (recipient == null) {
                                    recipientDomain = "@";
                                } else if (user == null) {
                                    recipientDomain = "@";
                                } else {
                                    int index = recipient.indexOf('@');
                                    recipientDomain = recipient.substring(index);
                                }
                                if (client != null && client.isBanActive()) {
                                    String key = Block.keyBlockKey(
                                            client, user, ip, helo, sender,
                                            fqdn, result, recipientDomain
                                    );
                                    results += "\nBLOCK registration to ban: " + key + "\n";
                                } else if (Core.isTestingVersion() && clientIP.isLoopbackAddress()) {
                                    String key = Block.keyBlockKey(
                                            client, user, ip, helo, sender,
                                            fqdn, result, recipientDomain
                                    );
                                    results += "\nBLOCK registration to ban: " + key + "\n";
                                }
                            }
                            TreeSet<Filter> filterSet = new TreeSet<>();
                            if ((envelopeFlag = Reputation.getEnvelopeFlag(ip, fqdn, helo, sender, result, user, recipient)) == HARMFUL) {
                                filterSet.add(Filter.ENVELOPE_HARMFUL);
                            } else if (envelopeFlag == UNDESIRABLE) {
                                filterSet.add(Filter.ENVELOPE_UNDESIRABLE);
                            }
                            if (usingSince < 7 && Abuse.isBlocked(client, user, ip, fqdn, sender, result)) {
                                filterSet.add(Filter.ABUSE_BLOCKED);
                            }
                            if (!filterSet.isEmpty()) {
                                results += "\n";
                                results += "Filters:\n";
                                for (Filter filter : filterSet) {
                                    results += "   ";
                                    results += filter.name();
                                    results += "\n";
                                }
                            }
                            results += "\n";
                            results += "Identifiers and status:\n";
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
                        } else if (!Core.isRunning() && user != null && user.usingHeader()) {
                            long timeKey = SPF.addQuery(
                                    clientIP, client, user, ip, helo, fqdn, sender,
                                    result, recipient, subaddress, tokenSet,
                                    "GREYLIST", "SYSTEM_SHUTDOWN"
                            );
                            timeKeySet.add(timeKey);
                            return "GREYLIST\n";
                        } else if (White.contains(client, user, ip, sender, fqdn, result, recipient, subaddress)) {
                            if (recipientTrapTime == null) {
                                Object[] resultSet = SPF.addQueryHam(
                                        clientIP, client, user, ip, helo, fqdn, sender,
                                        result, recipient, subaddress, tokenSet,
                                        "WHITE", "ORIGIN_WHITELISTED"
                                );
                                Long timeKey = (Long) resultSet[0];
                                timeKeySet.add(timeKey);
                                String ticket = (String) resultSet[1];
                                Block.clear(timeKey, client, user, ip, helo, sender, fqdn, result, recipient, "WHITE");
                                // Calcula frequencia de consultas.
                                String url = Core.getURL(user);
                                if (user != null && !user.usingHeader()) {
                                    if (White.containsKey(user, ip, fqdn, sender, result)) {
                                        Reputation.addBeneficial(client, user, ip, fqdn, helo, sender, result, recipient);
                                    } else {
                                        Reputation.addDesirable(client, user, ip, fqdn, helo, sender, result, recipient);
                                    }
                                }
                                return "WHITE " + (url == null ? ticket : url + ticket) + "\n";
                            } else {
                                Object[] resultSet = SPF.getTicket(
                                        clientIP, client, user, ip, helo, fqdn, sender,
                                        result, recipient, subaddress, tokenSet,
                                        "INEXISTENT", "RECIPIENT_INEXISTENT"
                                );
                                Long timeKey = (Long) resultSet[0];
                                timeKeySet.add(timeKey);
                                Reputation.addUnacceptable(client, user, ip, fqdn, helo, sender, result, recipient);
                                return "INEXISTENT\n";
                            }
                        } else if (Block.containsCIDR(ip) && Generic.isDynamicIP(ip)) {
                            Client.banDynamic(client, ip);
                            long time = Server.getNewUniqueTime();
                            SPF.setSpam(time, tokenSet);
                            Abuse.addHarmful(ip, fqdn);
                            CIDR.addHarmful(ip);
                            Abuse.reportAbuse(
                                    time, clientIP, client, user,
                                    sender, recipient,
                                    ip, fqdn, result, null
                            );
                            if (client != null && client.isBanActive()) {
                                return "BANNED\n";
                            } else {
                                return "BLOCKED\n";
                            }
                        } else if (Block.isBanned(client, user, ip, helo, fqdn, sender, result, recipient)) {
                            Client.ban(client, ip);
                            Object[] resultSet = null;
                            if (user != null) {
                                if (Block.ban(client, user, ip, helo, sender, fqdn, result, recipient)) {
                                    resultSet = SPF.addQuerySpam(
                                            clientIP, client, user, ip, helo, fqdn, sender,
                                            result, recipient, subaddress, tokenSet,
                                            "BLOCK", "ENVELOPE_BANNED"
                                    );
                                }
                            }
                            Long timeKey = (resultSet == null ? Server.getNewUniqueTime() : (Long) resultSet[0]);
                            timeKeySet.add(timeKey);
                            User.Query queryLocal = (resultSet == null ? null : (User.Query) resultSet[1]);
                            if (queryLocal == null) {
                                setSpam(timeKey, tokenSet);
                                Abuse.reportAbuse(
                                        timeKey, clientIP, client, user,
                                        sender, recipient,
                                        ip, fqdn, result, null
                                );
                            } else {
                                Abuse.offer(timeKey, queryLocal);
                            }
                            Reputation.addHarmful(client, user, ip, fqdn, helo, sender, result, recipient);
                            if (client != null && client.isBanActive()) {
                                return "BANNED\n";
                            } else {
                                return "BLOCKED\n";
                            }
                        } else if ((blockKey = Block.find(client, user, ip, sender, fqdn, result, recipient, true, true, true, true, true, true)) != null) {
                            if (Reputation.isHarmful(ip, fqdn, helo, sender, result)) {
                                Object[] resultSet = SPF.addQuerySpam(
                                        clientIP, client, user, ip, helo, fqdn, sender,
                                        result, recipient, subaddress, tokenSet,
                                        "BLOCK", "ENVELOPE_BLOCKED;" + blockKey
                                );
                                Long timeKey = (Long) resultSet[0];
                                timeKeySet.add(timeKey);
                                User.Query queryLocal = (User.Query) resultSet[1];
                                if (queryLocal == null) {
                                    Abuse.reportAbuse(
                                            timeKey, clientIP, client, user,
                                            sender, recipient,
                                            ip, fqdn, result, null
                                    );
                                } else {
                                    Abuse.offer(timeKey, queryLocal);
                                }
                                String url = Core.getUnblockURL(
                                        client, user, ip,
                                        sender, fqdn, recipient
                                );
                                Block.ban(
                                        client, user, ip, helo, sender,
                                        fqdn, result, recipient
                                );
                                Reputation.addHarmful(
                                        client, user, ip, fqdn, helo, sender, result, recipient
                                );
                                if (url == null) {
                                    return "BLOCKED\n";
                                } else {
                                    return "BLOCKED " + url + "\n";
                                }
                            } else if (fqdn == null && !result.equals("PASS") && !isHostname(helo)) {
                                Object[] resultSet = SPF.addQuerySpam(
                                        clientIP, client, user, ip, helo, fqdn, sender,
                                        result, recipient, subaddress, tokenSet,
                                        "BLOCK", "HELO_ANONYMOUS"
                                );
                                Long timeKey = (Long) resultSet[0];
                                timeKeySet.add(timeKey);
                                User.Query queryLocal = (User.Query) resultSet[1];
                                boolean banned = false;
                                String url = null;
                                if (queryLocal == null) {
                                    Abuse.reportAbuse(
                                            timeKey, clientIP, client, user,
                                            sender, recipient,
                                            ip, fqdn, result, null
                                    );
                                } else if (queryLocal.blockKey(timeKey, helo + ";INVALID")) {
                                    Abuse.offer(timeKey, queryLocal);
                                    url = Core.getUnblockURL(
                                            client, user, ip,
                                            sender, fqdn, recipient
                                    );
                                } else {
                                    Abuse.offer(timeKey, queryLocal);
                                    banned = Block.ban(
                                            client, user, ip, helo, sender,
                                            fqdn, result, recipient
                                    );
                                }
                                if (banned) {
                                    Abuse.addHarmful(ip, fqdn);
                                    CIDR.addHarmful(ip);
                                } else {
                                    Abuse.addUndesirable(ip, fqdn);
                                    CIDR.addUndesirable(ip);
                                }
                                if (url == null) {
                                    return "BLOCKED\n";
                                } else {
                                    return "BLOCKED " + url + "\n";
                                }
                            } else if (sender != null && spf != null && spf.isInexistent()) {
                                Object[] resultSet = SPF.addQuerySpam(
                                        clientIP, client, user, ip, helo, fqdn, sender,
                                        result, recipient, subaddress, tokenSet,
                                        "BLOCK", "SPF_NXDOMAIN"
                                );
                                Long timeKey = (Long) resultSet[0];
                                timeKeySet.add(timeKey);
                                User.Query queryLocal = (User.Query) resultSet[1];
                                String url = null;
                                if (recipientTrapTime == null) {
                                    url = Core.getUnblockURL(
                                            client, user, ip,
                                            sender, fqdn, recipient
                                    );
                                }
                                boolean banned = false;
                                if (queryLocal == null) {
                                    Abuse.reportAbuse(
                                            timeKey, clientIP, client, user,
                                            sender, recipient,
                                            ip, fqdn, result, url
                                    );
                                } else if (queryLocal.blockKey(timeKey, "NONE")) {
                                    Abuse.offer(timeKey, queryLocal);
                                } else if (queryLocal.blockKey(timeKey, sender + ";NXDOMAIN")) {
                                    Abuse.offer(timeKey, queryLocal);
                                } else if (spf.isDefinitelyInexistent()) {
                                    Abuse.offer(timeKey, queryLocal);
                                    banned = Block.ban(
                                            client, user, ip, helo, sender,
                                            fqdn, result, recipient
                                    );
                                    url = null;
                                } else {
                                    Abuse.offer(timeKey, queryLocal);
                                }
                                if (banned) {
                                    Reputation.addHarmful(
                                            client, user, ip, fqdn, helo, sender, result, recipient
                                    );
                                } else {
                                    Reputation.addUndesirable(
                                            client, user, ip, fqdn, helo, sender, result, recipient
                                    );
                                }
                                if (url == null) {
                                    return "BLOCKED\n";
                                } else {
                                    return "BLOCKED " + url + "\n";
                                }
                            } else if (recipientTrapTime == null) {
                                Action action = client == null ? Action.REJECT : client.getActionBLOCK();
                                if (action == Action.REJECT) {
                                    // Calcula frequencia de consultas.
                                    Object[] resultSet = SPF.addQuerySpam(
                                            clientIP, client, user, ip, helo, fqdn, sender,
                                            result, recipient, subaddress, tokenSet,
                                            "BLOCK", "ENVELOPE_BLOCKED;" + blockKey
                                    );
                                    Long timeKey = (Long) resultSet[0];
                                    timeKeySet.add(timeKey);
                                    User.Query queryLocal = (User.Query) resultSet[1];
                                    if (queryLocal != null && queryLocal.needHeader()) {
                                        String url = Core.getURL(user);
                                        String ticket = SPF.createTicket(timeKey, tokenSet);
                                        action = client == null ? Action.FLAG : client.getActionRED();
                                        if (action == Action.HOLD) {
                                            queryLocal.setResult("HOLD");
                                            return "HOLD " + (url == null ? ticket : url + ticket) + "\n";
                                        } else {
                                            queryLocal.setResult("FLAG");
                                            return "FLAG " + (url == null ? ticket : url + ticket) + "\n";
                                        }
                                    } else {
                                        String url = Core.getUnblockURL(
                                                client, user, ip,
                                                sender, fqdn, recipient
                                        );
                                        boolean banned = false;
                                        if (queryLocal == null) {
                                            Abuse.reportAbuse(
                                                    timeKey, clientIP, client, user,
                                                    sender, recipient,
                                                    ip, fqdn, result, url
                                            );
                                        } else if (NoReply.containsFQDN(fqdn)) {
                                            Abuse.offer(timeKey, queryLocal);
                                            banned = Block.ban(
                                                    client, user, ip, helo, sender,
                                                    fqdn, result, recipient
                                            );
                                            url = null;
                                        } else {
                                            Abuse.offer(timeKey, queryLocal);
                                        }
                                        if (banned) {
                                            Reputation.addHarmful(
                                                    client, user, ip, fqdn, helo, sender, result, recipient
                                            );
                                        } else {
                                            Reputation.addUndesirable(
                                                    client, user, ip, fqdn, helo, sender, result, recipient
                                            );
                                        }
                                        if (url == null) {
                                            return "BLOCKED\n";
                                        } else {
                                            return "BLOCKED " + url + "\n";
                                        }
                                    }
                                } else if (action == Action.FLAG) {
                                    Object[] resultSet = SPF.getTicket(
                                            clientIP, client, user, ip, helo, fqdn, sender,
                                            result, recipient, subaddress, tokenSet,
                                            "FLAG", "ENVELOPE_BLOCKED;" + blockKey
                                    );
                                    Long timeKey = (Long) resultSet[0];
                                    timeKeySet.add(timeKey);
                                    String ticket = (String) resultSet[1];
                                    String url = Core.getURL(user);
                                    return "FLAG " + (url == null ? ticket : url + ticket) + "\n";
                                } else if (action == Action.HOLD) {
                                    Object[] resultSet = SPF.getTicket(
                                            clientIP, client, user, ip, helo, fqdn, sender,
                                            result, recipient, subaddress, tokenSet,
                                            "HOLD", "ENVELOPE_BLOCKED;" + blockKey
                                    );
                                    Long timeKey = (Long) resultSet[0];
                                    timeKeySet.add(timeKey);
                                    String ticket = (String) resultSet[1];
                                    String url = Core.getURL(user);
                                    return "HOLD " + (url == null ? ticket : url + ticket) + "\n";
                                } else {
                                    return "ERROR: UNDEFINED ACTION\n";
                                }
                            } else {
                                Object[] resultSet = SPF.addQuerySpam(
                                        clientIP, client, user, ip, helo, fqdn, sender,
                                        result, recipient, subaddress, tokenSet,
                                        "BLOCK", "ENVELOPE_BLOCKED;" + blockKey
                                );
                                Long timeKey = (Long) resultSet[0];
                                User.Query queryLocal = (User.Query) resultSet[1];
                                if (queryLocal != null && !queryLocal.needHeader() && queryLocal.isHarmful()) {
                                    queryLocal.blockKey(timeKey, recipient + ";INEXISTENT");
                                }
                                boolean banned = false;
                                if (queryLocal == null) {
                                    Abuse.reportAbuse(
                                            timeKey, clientIP, client, user,
                                            sender, recipient,
                                            ip, fqdn, result, null
                                    );
                                } else if (System.currentTimeMillis() > recipientTrapTime) {
                                    // Spamtrap.
                                    Abuse.offer(timeKey, queryLocal);
                                    banned = Block.ban(
                                            client, user, ip, helo, sender,
                                            fqdn, result, recipient
                                    );
                                } else {
                                    Abuse.offer(timeKey, queryLocal);
                                }
                                if (banned) {
                                    Reputation.addHarmful(
                                            client, user, ip, fqdn, helo, sender, result, recipient
                                    );
                                } else {
                                    Reputation.addUndesirable(
                                            client, user, ip, fqdn, helo, sender, result, recipient
                                    );
                                }
                                return "BLOCKED\n";
                            }
                        } else if (sender != null && spf != null && spf.isDefinitelyInexistent()) {
                            Object[] resultSet = SPF.addQuerySpam(
                                    clientIP, client, user, ip, helo, fqdn, sender,
                                    result, recipient, subaddress, tokenSet,
                                    "NXDOMAIN", "SPF_NXDOMAIN"
                            );
                            Long timeKey = (Long) resultSet[0];
                            timeKeySet.add(timeKey);
                            if (Reputation.isUndesirable(ip, fqdn, helo, sender, result, user, recipient)) {
                                Block.addBlockKey(
                                        timeKey, client, user, ip, helo, sender,
                                        fqdn, result, null, "NXDOMAIN"
                                );
                            }
                            Reputation.addUnacceptable(
                                    client, user, ip, fqdn, helo, sender, result, recipient
                            );
                            return "NXDOMAIN\n";
                        } else if (result.equals("FAIL")) {
                            boolean hasActionHold = client == null ? false : client.hasActionHOLD();
                            boolean usingHeader = user == null ? false : user.usingHeader();
                            if (hasActionHold && usingHeader && recipientTrapTime == null) {
                                Object[] resultSet = SPF.getTicket(
                                        clientIP, client, user, ip, helo, fqdn, sender,
                                        result, recipient, subaddress, tokenSet,
                                        "HOLD", "SPF_FAIL"
                                );
                                Long timeKey = (Long) resultSet[0];
                                timeKeySet.add(timeKey);
                                String ticket = (String) resultSet[1];
                                String url = Core.getURL(user);
                                return "HOLD " + (url == null ? ticket : url + ticket) + "\n";
                            } else {
                                Object[] resultSet = SPF.addQuerySpam(
                                        clientIP, client, user, ip, helo, fqdn, sender,
                                        result, recipient, subaddress, tokenSet,
                                        "FAIL", "SPF_FAIL"
                                );
                                Long timeKey = (Long) resultSet[0];
                                timeKeySet.add(timeKey);
                                if (Reputation.isUndesirable(ip, fqdn, helo, sender, result, user, recipient)) {
                                    Block.addBlockKey(
                                            timeKey, client, user, ip, helo, sender,
                                            fqdn, result, null, "FAIL"
                                    );
                                }
                                Reputation.addUnacceptable(
                                        client, user, ip, fqdn, helo, sender, result, recipient
                                );
                                return "FAIL\n";
                            }
                        } else if (sender != null && !Domain.isMailFrom(sender)) {
                            boolean hasActionHold = client == null ? false : client.hasActionHOLD();
                            boolean usingHeader = user == null ? false : user.usingHeader();
                            if (hasActionHold && usingHeader && recipientTrapTime == null) {
                                Object[] resultSet = SPF.getTicket(
                                        clientIP, client, user, ip, helo, fqdn, sender,
                                        result, recipient, subaddress, tokenSet,
                                        "HOLD", "ENVELOPE_INVALID;SENDER"
                                );
                                Long timeKey = (Long) resultSet[0];
                                timeKeySet.add(timeKey);
                                String ticket = (String) resultSet[1];
                                String url = Core.getURL(user);
                                return "HOLD " + (url == null ? ticket : url + ticket) + "\n";
                            } else {
                                Object[] resultSet = SPF.addQuerySpam(
                                        clientIP, client, user, ip, helo, fqdn, sender,
                                        result, recipient, subaddress, tokenSet,
                                        "INVALID", "ENVELOPE_INVALID;SENDER"
                                );
                                Long timeKey = (Long) resultSet[0];
                                timeKeySet.add(timeKey);
                                if (Reputation.isUndesirable(ip, fqdn, helo, sender, result, user, recipient)) {
                                    Block.addBlockKey(
                                            timeKey, client, user, ip, helo, sender,
                                            fqdn, result, null, "INVALID"
                                    );
                                }
                                Reputation.addUnacceptable(client, user, ip, fqdn, helo, sender, result, recipient);
                                return "INVALID\n";
                            }
                        } else if (sender != null && !result.equals("PASS") && Domain.isOfficialTLD(sender)) {
                            Object[] resultSet = SPF.addQuerySpam(
                                    clientIP, client, user, ip, helo, fqdn, sender,
                                    result, recipient, subaddress, tokenSet,
                                    "INVALID", "SPF_TLD"
                            );
                            Long timeKey = (Long) resultSet[0];
                            timeKeySet.add(timeKey);
                            if (Reputation.isUndesirable(ip, fqdn, helo, sender, result, user, recipient)) {
                                Block.addBlockKey(
                                        timeKey, client, user, ip, helo, sender,
                                        fqdn, result, null, "RESERVED"
                                );
                            }
                            Reputation.addUnacceptable(client, user, ip, fqdn, helo, sender, result, recipient);
                            return "INVALID\n";
                        } else if (recipient != null && !isValidRecipient(recipient)) {
                            Object[] resultSet = SPF.getTicket(
                                    clientIP, client, user, ip, helo, fqdn, sender,
                                    result, recipient, subaddress, tokenSet,
                                    "INEXISTENT", "RECIPIENT_INEXISTENT"
                            );
                            Long timeKey = (Long) resultSet[0];
                            timeKeySet.add(timeKey);
                            Reputation.addUnacceptable(client, user, ip, fqdn, helo, sender, result, recipient);
                            return "INEXISTENT\n";
                        } else if (sender != null && !result.equals("PASS") && fqdn == null) {
                            boolean hasActionHold = client == null ? false : client.hasActionHOLD();
                            boolean usingHeader = user == null ? false : user.usingHeader();
                            if (hasActionHold && usingHeader && recipientTrapTime == null) {
                                Object[] resultSet = SPF.getTicket(
                                        clientIP, client, user, ip, helo, fqdn, sender,
                                        result, recipient, subaddress, tokenSet,
                                        "HOLD", "ENVELOPE_INVALID;NOTPASS"
                                );
                                Long timeKey = (Long) resultSet[0];
                                timeKeySet.add(timeKey);
                                String ticket = (String) resultSet[1];
                                String url = Core.getURL(user);
                                return "HOLD " + (url == null ? ticket : url + ticket) + "\n";
                            } else if (spf != null && spf.isTemporary()) {
                                long timeKey = SPF.addQuery(
                                        clientIP, client, user, ip, helo, fqdn, sender,
                                        result, recipient, subaddress, tokenSet,
                                        "GREYLIST", "SPF_TEMP_ERROR"
                                );
                                timeKeySet.add(timeKey);
                                return "GREYLIST\n";
                            } else {
                                Object[] resultSet = SPF.addQuerySpam(
                                        clientIP, client, user, ip, helo, fqdn, sender,
                                        result, recipient, subaddress, tokenSet,
                                        "INVALID", "ENVELOPE_INVALID;NOTPASS"
                                );
                                Long timeKey = (Long) resultSet[0];
                                timeKeySet.add(timeKey);
                                if (Reputation.isUndesirable(ip, fqdn, helo, sender, result, user, recipient)) {
                                    Block.addBlockKey(
                                            timeKey, client, user, ip, helo, sender,
                                            fqdn, result, null, "INVALID"
                                    );
                                }
                                Reputation.addUnacceptable(client, user, ip, fqdn, helo, sender, result, recipient);
                                return "INVALID\n";
                            }
                        } else if (recipientTrapTime != null) {
                            Reputation.addUnacceptable(client, user, ip, fqdn, helo, sender, result, recipient);
                            if (System.currentTimeMillis() > recipientTrapTime) {
                                // Spamtrap
                                Object[] resultSet = SPF.getTicket(
                                        clientIP, client, user, ip, helo, fqdn, sender,
                                        result, recipient, subaddress, tokenSet,
                                        "TRAP", "RECIPIENT_TRAP"
                                );
                                Long timeKey = (Long) resultSet[0];
                                timeKeySet.add(timeKey);
                                if (Math.random() > 0.8d) {
                                    Block.addBlockKey(
                                            timeKey, client, user, ip, helo, sender,
                                            fqdn, result, null, recipient + ";SPAMTRAP"
                                    );
                                }
                                return "SPAMTRAP\n";
                            } else {
                                // Inexistent
                                Object[] resultSet = SPF.getTicket(
                                        clientIP, client, user, ip, helo, fqdn, sender,
                                        result, recipient, subaddress, tokenSet,
                                        "INEXISTENT", "RECIPIENT_INEXISTENT"
                                );
                                Long timeKey = (Long) resultSet[0];
                                timeKeySet.add(timeKey);
                                return "INEXISTENT\n";
                            }
                        } else if (recipient != null && recipient.startsWith("postmaster@")) {
                            Object[] resultSet = SPF.getTicket(
                                    clientIP, client, user, ip, helo, fqdn, sender,
                                    result, recipient, subaddress, tokenSet,
                                    "ACCEPT", "RECIPIENT_POSTMASTER"
                            );
                            Long timeKey = (Long) resultSet[0];
                            timeKeySet.add(timeKey);
                            String ticket = (String) resultSet[1];
                            String url = Core.getURL(user);
                            if (user != null && !user.usingHeader()) {
                                Reputation.addAcceptable(client, user, ip, fqdn, helo, sender, result, recipient);
                            }
                            return result + " " + (url == null ? ticket : url + URLEncoder.encode(ticket, "UTF-8")) + "\n";
                        } else if (usingSince < 7 && Abuse.isBlocked(client, user, ip, fqdn, sender, result)) {
                            if (user != null && user.usingHeader()) {
                                Object[] resultSet = SPF.getTicket(
                                        clientIP, client, user, ip, helo, fqdn, sender,
                                        result, recipient, subaddress, tokenSet,
                                        "FLAG", "ABUSE_BLOCKED"
                                );
                                Long timeKey = (Long) resultSet[0];
                                timeKeySet.add(timeKey);
                                String ticket = (String) resultSet[1];
                                String url = Core.getURL(user);
                                return "FLAG " + (url == null ? ticket : url + ticket) + "\n";
                            } else {
                                Action action = client == null ? Action.REJECT : client.getActionRED();
                                if (action == Action.REJECT) {
                                    Object[] resultSet = SPF.addQuerySpam(
                                            clientIP, client, user, ip, helo, fqdn, sender,
                                            result, recipient, subaddress, tokenSet,
                                            "REJECT", "ABUSE_BLOCKED"
                                    );
                                    Long timeKey = (Long) resultSet[0];
                                    User.Query queryLocal = (User.Query) resultSet[1];
                                    if (queryLocal == null) {
                                        Abuse.reportAbuse(
                                                timeKey, clientIP, client, user,
                                                sender, recipient,
                                                ip, fqdn, result, null
                                        );
                                    } else {
                                        Abuse.offer(timeKey, queryLocal);
                                    }
                                    timeKeySet.add(timeKey);
                                    Block.addBlockKey(
                                            timeKey, client, user, ip, helo, sender,
                                            fqdn, result, null, "ABUSE_BLOCKED"
                                    );
                                    Reputation.addUndesirable(
                                            client, user, ip, fqdn,
                                            helo, sender, result, recipient
                                    );
                                    String url = Core.getUnblockURL(
                                            client, user, ip,
                                            sender, fqdn, recipient
                                    );
                                    if (url == null) {
                                        return "BLOCKED\n";
                                    } else {
                                        return "BLOCKED " + url + "\n";
                                    }
                                } else if (action == Action.DEFER) {
                                    if (Defer.defer(fluxo, Core.getDeferTimeRED())) {
                                        String url = Core.getReleaseURL(user, fluxo);
                                        SPF.addQuery(
                                                clientIP, client, user, ip, helo, fqdn, sender,
                                                result, recipient, subaddress, tokenSet,
                                                "LISTED", "ABUSE_BLOCKED"
                                        );
                                        if (url == null || Defer.count(fluxo) > 1) {
                                            return "LISTED\n";
                                        } else if (result.equals("PASS") && enviarLiberacao(url, sender, recipient)) {
                                            return "LISTED\n";
                                        } else {
                                            return "LISTED " + url + "\n";
                                        }
                                    } else {
                                        Object[] resultSet = SPF.addQuerySpam(
                                                clientIP, client, user, ip, helo, fqdn, sender,
                                                result, recipient, subaddress, tokenSet,
                                                "REJECT", "ABUSE_BLOCKED"
                                        );
                                        Long timeKey = (Long) resultSet[0];
                                        timeKeySet.add(timeKey);
                                        Reputation.addUnacceptable(client, user, ip, fqdn, helo, sender, result, recipient);
                                        return "BLOCKED\n";
                                    }
                                } else if (action == Action.FLAG) {
                                    Object[] resultSet = SPF.getTicket(
                                            clientIP, client, user, ip, helo, fqdn, sender,
                                            result, recipient, subaddress, tokenSet,
                                            "FLAG", "ABUSE_BLOCKED"
                                    );
                                    Long timeKey = (Long) resultSet[0];
                                    timeKeySet.add(timeKey);
                                    String ticket = (String) resultSet[1];
                                    String url = Core.getURL(user);
                                    return "FLAG " + (url == null ? ticket : url + ticket) + "\n";
                                } else if (action == Action.HOLD) {
                                    Object[] resultSet = SPF.getTicket(
                                            clientIP, client, user, ip, helo, fqdn, sender,
                                            result, recipient, subaddress, tokenSet,
                                            "HOLD", "ABUSE_BLOCKED"
                                    );
                                    Long timeKey = (Long) resultSet[0];
                                    timeKeySet.add(timeKey);
                                    String ticket = (String) resultSet[1];
                                    String url = Core.getURL(user);
                                    return "HOLD " + (url == null ? ticket : url + ticket) + "\n";
                                } else {
                                    return "ERROR: UNDEFINED ACTION\n";
                                }
                            }
                        } else if ((envelopeFlag = Reputation.getEnvelopeFlag(ip, fqdn, helo, sender, result, user, recipient)) == HARMFUL || envelopeFlag == UNDESIRABLE) {
                            if (user != null && user.usingHeader()) {
                                Object[] resultSet = SPF.getTicket(
                                        clientIP, client, user, ip, helo, fqdn, sender,
                                        result, recipient, subaddress, tokenSet,
                                        "FLAG", "ENVELOPE_" + envelopeFlag
                                );
                                Long timeKey = (Long) resultSet[0];
                                timeKeySet.add(timeKey);
                                String ticket = (String) resultSet[1];
                                String url = Core.getURL(user);
                                return "FLAG " + (url == null ? ticket : url + ticket) + "\n";
                            } else {
                                Action action = client == null ? Action.REJECT : client.getActionRED();
                                if (action == Action.REJECT) {
                                    Object[] resultSet = SPF.addQuerySpam(
                                            clientIP, client, user, ip, helo, fqdn, sender,
                                            result, recipient, subaddress, tokenSet,
                                            "REJECT", "ENVELOPE_" + envelopeFlag
                                    );
                                    Long timeKey = (Long) resultSet[0];
                                    User.Query queryLocal = (User.Query) resultSet[1];
                                    if (queryLocal == null) {
                                        Abuse.reportAbuse(
                                                timeKey, clientIP, client, user,
                                                sender, recipient,
                                                ip, fqdn, result, null
                                        );
                                    } else {
                                        Abuse.offer(timeKey, queryLocal);
                                    }
                                    timeKeySet.add(timeKey);
                                    Reputation.addUnacceptable(
                                            client, user, ip, fqdn, helo,
                                            sender, result, recipient
                                    );
                                    String url = Core.getUnblockURL(
                                            client, user, ip,
                                            sender, fqdn, recipient
                                    );
                                    if (url == null) {
                                        return "BLOCKED\n";
                                    } else {
                                        return "BLOCKED " + url + "\n";
                                    }
                                } else if (action == Action.DEFER) {
                                    if (Defer.defer(fluxo, Core.getDeferTimeRED())) {
                                        String url = Core.getReleaseURL(user, fluxo);
                                        SPF.addQuery(
                                                clientIP, client, user, ip, helo, fqdn, sender,
                                                result, recipient, subaddress, tokenSet,
                                                "LISTED", "ENVELOPE_" + envelopeFlag
                                        );
                                        if (url == null || Defer.count(fluxo) > 1) {
                                            return "LISTED\n";
                                        } else if (result.equals("PASS") && enviarLiberacao(url, sender, recipient)) {
                                            return "LISTED\n";
                                        } else {
                                            return "LISTED " + url + "\n";
                                        }
                                    } else {
                                        Object[] resultSet = SPF.addQuerySpam(
                                                clientIP, client, user, ip, helo, fqdn, sender,
                                                result, recipient, subaddress, tokenSet,
                                                "REJECT", "ENVELOPE_" + envelopeFlag
                                        );
                                        Long timeKey = (Long) resultSet[0];
                                        timeKeySet.add(timeKey);
                                        Reputation.addUnacceptable(client, user, ip, fqdn, helo, sender, result, recipient);
                                        return "BLOCKED\n";
                                    }
                                } else if (action == Action.FLAG) {
                                    Object[] resultSet = SPF.getTicket(
                                            clientIP, client, user, ip, helo, fqdn, sender,
                                            result, recipient, subaddress, tokenSet,
                                            "FLAG", "ENVELOPE_" + envelopeFlag
                                    );
                                    Long timeKey = (Long) resultSet[0];
                                    timeKeySet.add(timeKey);
                                    String ticket = (String) resultSet[1];
                                    String url = Core.getURL(user);
                                    return "FLAG " + (url == null ? ticket : url + ticket) + "\n";
                                } else if (action == Action.HOLD) {
                                    Object[] resultSet = SPF.getTicket(
                                            clientIP, client, user, ip, helo, fqdn, sender,
                                            result, recipient, subaddress, tokenSet,
                                            "HOLD", "ENVELOPE_" + envelopeFlag
                                    );
                                    Long timeKey = (Long) resultSet[0];
                                    timeKeySet.add(timeKey);
                                    String ticket = (String) resultSet[1];
                                    String url = Core.getURL(user);
                                    return "HOLD " + (url == null ? ticket : url + ticket) + "\n";
                                } else {
                                    return "ERROR: UNDEFINED ACTION\n";
                                }
                            }
                        } else if (result.equals("PASS") && Reputation.isDesirable(ip, fqdn, helo, sender, result)) {
                            Object[] resultSet = SPF.addQueryHam(
                                    clientIP, client, user, ip, helo, fqdn, sender,
                                    result, recipient, subaddress, tokenSet,
                                    "ACCEPT", null
                            );
                            Long timeKey = (Long) resultSet[0];
                            timeKeySet.add(timeKey);
                            String ticket = (String) resultSet[1];
                            String url = Core.getURL(user);
                            if (user != null && !user.usingHeader()) {
                                Reputation.addAcceptable(client, user, ip, fqdn, helo, sender, result, recipient);
                            }
                            return "PASS " + (url == null ? ticket : url + URLEncoder.encode(ticket, "UTF-8")) + "\n";
                        } else if (Provider.containsFQDN(fqdn)) {
                            Object[] resultSet = SPF.addQueryHam(
                                    clientIP, client, user, ip, helo, fqdn, sender,
                                    result, recipient, subaddress, tokenSet,
                                    "ACCEPT", "FQDN_PROVIDER"
                            );
                            Long timeKey = (Long) resultSet[0];
                            timeKeySet.add(timeKey);
                            String ticket = (String) resultSet[1];
                            String url = Core.getURL(user);
                            if (user != null && !user.usingHeader()) {
                                Reputation.addAcceptable(client, user, ip, fqdn, helo, sender, result, recipient);
                            }
                            return result + " " + (url == null ? ticket : url + URLEncoder.encode(ticket, "UTF-8")) + "\n";
                        } else if ((result.equals("SOFTFAIL") || usingSince < 7) && Defer.defer(fluxo, Core.getDeferTimeSOFTFAIL())) {
                            long timeKey;
                            if (result.equals("SOFTFAIL")) {
                                timeKey = SPF.addQuery(
                                        clientIP, client, user, ip, helo, fqdn, sender,
                                        result, recipient, subaddress, tokenSet,
                                        "GREYLIST", "SPF_SOFTFAIL"
                                );
                            } else {
                                timeKey = SPF.addQuery(
                                        clientIP, client, user, ip, helo, fqdn, sender,
                                        result, recipient, subaddress, tokenSet,
                                        "GREYLIST", "DOMAIN_EMERGED;" + usingSince
                                );
                            }
                            timeKeySet.add(timeKey);
                            return "GREYLIST\n";
                        } else {
                            Object[] resultSet = SPF.addQueryHam(
                                    clientIP, client, user, ip, helo, fqdn, sender,
                                    result, recipient, subaddress, tokenSet,
                                    "ACCEPT", null
                            );
                            Long timeKey = (Long) resultSet[0];
                            timeKeySet.add(timeKey);
                            String ticket = (String) resultSet[1];
                            String url = Core.getURL(user);
                            return result + " " + (url == null ? ticket : url + URLEncoder.encode(ticket, "UTF-8")) + "\n";
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
                && isValidEmail(remetente)
                && isValidEmail(destinatario)
                && url != null
                && !NoReply.contains(remetente, true)
                ) {
            try {
                Locale locale = Core.getDefaultLocale(remetente);
                InternetAddress[] recipients = InternetAddress.parse(remetente);
                MimeMessage message = Core.newMessage(false);
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
                File logoFile = Core.getLogoFile(null);
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
                return ServerSMTP.sendMessage(locale, message, recipients, null);
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
        return Core.encryptURL(time, ticket);
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
                if (token.startsWith("@") && isHostname(token.substring(1))) {
                    token = '.' + token.substring(1);
                    expandDomain = true;
                } else if (!token.startsWith("@") && Domain.isMailFrom(token)) {
                    expandDomain = false;
                } else if (token.startsWith(".") && isHostname(token.substring(1))) {
                    expandDomain = true;
                } else if (!token.startsWith(".") && isHostname(token)) {
                    token = '.' + token;
                    expandDomain = true;
                } else {
                    expandDomain = false;
                }
                if (expandDomain) {
                    try {
                        String dominio = Domain.extractDomain(token, true);
                        if (dominio != null && !Provider.contains(dominio) && !Ignore.contains(dominio)) {
                            expandedSet.add(dominio);
                        }
                    } catch (ProcessException ex) {
                        // Do nothing.
                    }
                }
            }
        }
        return expandedSet;
    }
    
    public static String getPostfixTicketHOLD(
            InetAddress clientIP,
            Client client,
            User user,
            String ip,
            String helo,
            String hostname,
            String sender,
            String qualifier,
            String recipient,
            String subaddress,
            String instance,
            TreeSet<String> tokenSet,
            String filter
            ) throws ProcessException {
        long time = Server.getNewUniqueTime();
        if (user != null) {
            Query query = user.addQuery(
                    time, clientIP, client, ip, helo, hostname,
                    sender, qualifier, recipient, subaddress,
                    tokenSet, "HOLD", filter
            );
            query.setPostfixHOLD(instance);
        }
        return SPF.createTicket(time, tokenSet);
    }
    
    public static String getPostfixTicketFLAG(
            InetAddress clientIP,
            Client client,
            User user,
            String ip,
            String helo,
            String hostname,
            String sender,
            String qualifier,
            String recipient,
            String subaddress,
            String instance,
            TreeSet<String> tokenSet,
            String filter
            ) throws ProcessException {
        long time = Server.getNewUniqueTime();
        if (user != null) {
            Query query = user.addQuery(
                    time, clientIP, client, ip, helo, hostname,
                    sender, qualifier, recipient, subaddress,
                    tokenSet, "FLAG", filter
            );
            query.setPostfixFLAG(instance);
        }
        return SPF.createTicket(time, tokenSet);
    }
    
    public static Object[] getTicket(
            InetAddress clientIP,
            Client client,
            User user,
            String ip,
            String helo,
            String hostname,
            String sender,
            String qualifier,
            String recipient,
            String subaddress,
            TreeSet<String> tokenSet,
            String result,
            String filter
            ) throws ProcessException {
        long timeKey;
        if (user == null) {
            timeKey = Server.getNewUniqueTime();
        } else {
            Object[] resultSet = user.getDeferedQuery(
                    ip, hostname, sender, recipient, result
            );
            if (resultSet == null) {
                timeKey = Server.getNewUniqueTime();
                user.addQuery(
                        timeKey, clientIP, client, ip, helo, hostname,
                        sender, qualifier, recipient, subaddress,
                        tokenSet, result, filter
                );
                user.setDeferedQuery(
                        timeKey, ip, hostname, sender, recipient, result
                );
            } else {
                timeKey = (Long) resultSet[0];
            }
        }
        Object[] resultSet = new Object[2];
        resultSet[0] = timeKey;
        resultSet[1] = SPF.createTicket(timeKey, tokenSet);
        return resultSet;
    }
                    
    public static Object[] addQueryHam(
            InetAddress clientIP,
            Client client,
            User user,
            String ip,
            String helo,
            String hostname,
            String sender,
            String qualifier,
            String recipient,
            String subaddress,
            TreeSet<String> tokenSet,
            String result,
            String filter
            ) throws ProcessException {
        long timeKey;
        if (user == null) {
            timeKey = Server.getNewUniqueTime();
        } else {
            Object[] resultSet = user.getDeferedQuery(
                    ip, hostname, sender, recipient, result
            );
            if (resultSet == null) {
                user.addQuery(
                        timeKey = Server.getNewUniqueTime(),
                        clientIP, client, ip, helo, hostname, sender,
                        qualifier, recipient, subaddress, tokenSet,
                        result, filter
                );
                user.setDeferedQuery(
                        timeKey, ip, hostname, sender, recipient, result
                );
            } else {
                timeKey = (Long) resultSet[0];
            }
        }
        for (String token : expandTokenSet(tokenSet)) {
            if (isValidReputation(token)) {
                Distribution distribution = CacheDistribution.get(token, true);
                distribution.addQueryHam(timeKey);
                distribution.getStatus(token);
            }
        }
        Object[] resultSet = new Object[2];
        resultSet[0] = timeKey;
        resultSet[1] = SPF.createTicket(timeKey, tokenSet);
        return resultSet;
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
            InetAddress clientIP,
            Client client,
            User user,
            String ip,
            String helo,
            String hostname,
            String sender,
            String qualifier,
            String recipient,
            String subaddress,
            TreeSet<String> tokenSet,
            String result,
            String filter
            ) throws ProcessException {
        long timeKey;
        Object[] resultSet;
        if (user == null) {
            timeKey = Server.getNewUniqueTime();
            resultSet = new Object[2];
            resultSet[0] = timeKey;
            resultSet[1] = null;
        } else {
            resultSet = user.getDeferedQuery(
                    ip, hostname, sender, recipient, result
            );
            if (resultSet == null) {
                timeKey = Server.getNewUniqueTime();
                resultSet = new Object[2];
                resultSet[0] = timeKey;
                resultSet[1] = user.addQuery(
                        timeKey, clientIP, client, ip, helo, hostname, sender,
                        qualifier, recipient, subaddress, tokenSet,
                        result, filter
                );
                user.setDeferedQuery(
                        timeKey, ip, hostname, sender, recipient, result
                );
            } else {
                timeKey = (Long) resultSet[0];
            }
        }
        for (String token : expandTokenSet(tokenSet)) {
            if (isValidReputation(token)) {
                Distribution distribution = CacheDistribution.get(token, true);
                if (Ignore.contains(token)) {
                    distribution.addQueryHam(timeKey);
                    distribution.getStatus(token);
                } else {
                    distribution.addQuerySpam(timeKey);
                    distribution.getStatus(token);
                    Peer.sendToAll(token, distribution);
                }
            }
        }
        return resultSet;
    }
    
    public static long addQuery(
            InetAddress clientIP,
            Client client,
            User user,
            String ip,
            String helo,
            String hostname,
            String sender,
            String qualifier,
            String recipient,
            String subaddress,
            TreeSet<String> tokenSet,
            String result,
            String filter
            ) throws ProcessException {
        if (user == null) {
            return Server.getNewUniqueTime();
        } else {
            Object[] resultSet = user.getDeferedQuery(
                    ip, hostname, sender, recipient, result
            );
            if (resultSet == null) {
                long timeKey = Server.getNewUniqueTime();
                user.addQuery(
                        timeKey, clientIP, client, ip, helo, hostname, sender,
                        qualifier, recipient, subaddress, tokenSet,
                        result, filter
                );
                user.setDeferedQuery(
                        timeKey, ip, hostname, sender, recipient, result
                );
                return timeKey;
            } else {
                return Server.getNewUniqueTime();
            }
        }
    }
    
    public static void createDistribution(String token) {
        Distribution distribution = CacheDistribution.get(token, true);
        if (distribution != null) {
            distribution.getStatus(token);
        }
    }
    
    public static Status getStatus(String token, boolean refresh) {
        if (token == null) {
            return null;
        } else {
            Distribution distribution = CacheDistribution.get(token, false);
            if (distribution == null) {
                return Status.GREEN;
            } else if (refresh) {
                return distribution.getStatus(token);
            } else {
                return distribution.getStatus();
            }
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
    
    private static float getSpamProbabilityFast(String token) {
        Distribution distribution = CacheDistribution.get(token, false);
        if (distribution == null) {
            return 0.0f;
        } else {
            return distribution.getSpamProbability();
        }
    }
    
    public static int getDistributionCount(String token) {
        if (isValidReputation(token)) {
            Distribution distribution = CacheDistribution.get(token, false);
            if (distribution == null) {
                return 0;
            } else {
                return distribution.getTotalSize();
            }
        } else {
            return 0;
        }
    }
    
    public static boolean isGreen(String token) {
        if (isValidReputation(token)) {
            Distribution distribution = CacheDistribution.get(token, false);
            if (distribution == null) {
                return false;
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
    
    public static boolean isRed(String token) {
        if (isValidReputation(token)) {
            Distribution distribution = CacheDistribution.get(token, false);
            if (distribution == null) {
                // Distribuição não encontrada.
                // Considerar que não está listado.
                return false;
            } else {
                return distribution.isRed(token);
            }
        } else {
            return false;
        }
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
        
        public static Status parse(String name) {
            if (name == null) {
                return null;
            } else {
                try {
                    return Status.valueOf(name);
                } catch (IllegalArgumentException ex) {
                    return null;
                }
            }
        }
    }
    
    private static Distribution newDistribution(
            Long creation,
            Long lastQuery,
            Status status,
            NormalDistribution frequency,
            boolean good
    ) {
        if (creation == null) {
            return null;
        } else if (lastQuery == null) {
            return null;
        } else if (status == null) {
            return null;
        } else if (frequency == null) {
            return null;
        } else {
            return new Distribution(
                    creation, lastQuery,
                    status, frequency, good
            );
        }
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
        
        private long creation = System.currentTimeMillis();
        private long lastQuery; // Última consulta à distribuição.
        private Status status; // Status atual da distribuição.
        private NormalDistribution frequency = null; // Frequência média em segundos.
        
        private TreeSet<Long> hamSet = new TreeSet<>();
        private TreeSet<Long> spamSet = new TreeSet<>();
        private boolean good = false;
        
        private boolean store(String key, FileWriter writer) throws IOException {
            if (key == null) {
                return false;
            } else if (status == null) {
                return false;
            } else if (frequency == null) {
                return false;
            } else {
                Float[] xiResult = frequency.getXiSum();
                writer.write("ADDR ");
                writer.write(key);
                writer.write(' ');
                writer.write(Long.toString(creation, 32));
                writer.write(' ');
                writer.write(Long.toString(lastQuery, 32));
                writer.write(' ');
                writer.write(status.name());
                writer.write(' ');
                writer.write(Float.toString(xiResult[0]));
                writer.write(' ');
                writer.write(Float.toString(xiResult[1]));
                writer.write(' ');
                writer.write(Boolean.toString(good));
                writer.write('\n');
                writer.flush();
                for (long timeKey : hamSet) {
                    writer.write("ADDH ");
                    writer.write(key);
                    writer.write(' ');
                    writer.write(Long.toString(timeKey, 32));
                    writer.write('\n');
                    writer.flush();
                }
                for (long timeKey : spamSet) {
                    writer.write("ADDS ");
                    writer.write(key);
                    writer.write(' ');
                    writer.write(Long.toString(timeKey, 32));
                    writer.write('\n');
                    writer.flush();
                }
                return true;
            }
        }

        private Distribution(
                long creation,
                long lastQuery,
                Status status,
                NormalDistribution frequency,
                boolean good
        ) {
            this.creation = creation;
            this.lastQuery = lastQuery;
            this.status = status;
            this.frequency = frequency;
            this.good = good;
        }
        
        public Distribution() {
            lastQuery = 0;
            status = Status.GREEN;
        }
        
        public synchronized void reset() {
            hamSet.clear();
            spamSet.clear();
            lastQuery = 0;
            status = Status.GREEN;
            frequency = null;
        }
        
        public synchronized Distribution replicate() {
            Distribution clone = new Distribution();
            clone.lastQuery = this.lastQuery;
            clone.status = this.status;
            clone.frequency = this.frequency == null ? null : this.frequency.replicate();
            clone.hamSet.addAll(this.hamSet);
            clone.spamSet.addAll(this.spamSet);
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
        
        public synchronized float getSpamProbability() {
            int ham = hamSet.size();
            int spam = spamSet.size();
            int total = ham + spam;
            if (total == 0) {
                return 0.0f;
            } else {
                return (float) spam / (float) total;
            }
        }
        
        public float getSpamProbability(String token) {
            Float probability = getSpamProbability(token, 8);
            if (probability == null) {
                return 0.0f;
            } else {
                return probability;
            }
        }
        
        public Float getSpamProbability(String token, int limit) {
            int[] binomial = getBinomial();
            if (token != null) {
                for (Peer peer : Peer.getPeerList()) {
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
            if ((System.currentTimeMillis() - creation) > Server.WEEK_TIME) {
                good = binomial[0] > 512 && binomial[1] < 32;
            }
            int total = binomial[0] + binomial[1];
            if (total < limit) {
                return null;
            } else {
                float probability = (float) binomial[1] / (float) total;
                if (probability > LIMIAR1 && binomial[1] < 32) {
                    return LIMIAR1;
                } else if (probability > LIMIAR2 && binomial[1] < 64) {
                    return LIMIAR2;
                } else if (probability > LIMIAR3 && binomial[1] < 128) {
                    return LIMIAR3;
                } else {
                    return probability;
                }
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

        public synchronized boolean removeSpam(long time) {
            hamSet.add(time);
            spamSet.remove(time);
            return true;
        }
        
        public void hairCut() {
            while (getTotalSize() > Core.getReputationLimit()) {
                long firstHam = hamSet.isEmpty() ? Long.MAX_VALUE : hamSet.first();
                long firstSpam = spamSet.isEmpty() ? Long.MAX_VALUE : spamSet.first();
                long time = Math.min(firstHam, firstSpam);
                hamSet.remove(time);
                spamSet.remove(time);
            }
        }

        public synchronized boolean addSpam(long time) {
            boolean hamChanged = hamSet.remove(time);
            boolean spamChanged = spamSet.add(time);
            boolean changed = hamChanged || spamChanged;
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
            hairCut();
            return changed;
        }
        
        public int[] getBinomial() {
            int[] result = new int[2];
            result[0] = hamSet.size();
            result[1] = spamSet.size();
            return result;
        }
        
        public int[] getBinomial(String token) {
            int[] result = new int[2];
            if (token != null) {
                for (Peer peer : Peer.getPeerList()) {
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
            result[0] += hamSet.size();
            result[1] += spamSet.size();
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
            } else if (probability > LIMIAR1 && spam < 32) {
                return LIMIAR1;
            } else if (probability > LIMIAR2 && spam < 64) {
                return LIMIAR2;
            } else if (probability > LIMIAR3 && spam < 128) {
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
