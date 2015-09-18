/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.com.allchemistry.spf;

import br.com.allchemistry.core.Main;
import br.com.allchemistry.core.NormalDistribution;
import br.com.allchemistry.whois.Domain;
import br.com.allchemistry.core.ProcessException;
import br.com.allchemistry.core.Server;
import br.com.allchemistry.whois.Owner;
import br.com.allchemistry.whois.Subnet;
import br.com.allchemistry.whois.SubnetIPv4;
import br.com.allchemistry.whois.SubnetIPv6;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.Timer;
import java.util.TimerTask;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.naming.CommunicationException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.InvalidAttributeIdentifierException;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Representa o registro SPF de um deterninado hostname.
 * 
 * Implementação da RFC 7208, com algumas 
 * modificações para atender condições específicas.
 * 
 * Quando a consulta é feita, o resultado do SPF é considerado para determinar o
 * responsável pela mensagem. Uma vez encontrado o responsável, um ticket SPFBL
 * é gerado através de criptografia na base 64. Este ticket é enviado juntamente
 * o qualificador SPF da consulta. O cliente da consulta deve extrair o ticket
 * do resultado e adicionar no cabeçalho da mensagem utilizando o campo
 * "Received-SPFBL".
 * 
 * A regra de determinação de responsabilidade é usada para gerar o ticket SPFBL
 * e funciona da seguinte forma:
 *    1. Se retornar PASS, o remetente é o responsável pela mensagem ou
 *    2. Caso contrário, o hostname é responsável pela mensagem.
 * 
 * No primeiro caso, onde o remetente é responsável pela mensagem, o ticket é
 * gerado com a seguinte regra:
 *    1. Se o domínio do rementente estiver na lista de provedores, 
 *       então o endereço de e-mail completo é utilizado ou
 *    2. Caso contrário, o hostname e domínio do rementente são utilizados.
 * 
 * No segundo caso, onde o hostname é responsável pela mensagem, o ticket é gerado
 * com a seguinte regra:
 *    1. Se o HELO apontar para o IP, então o próprio HELO e 
 *       o domínio do HELO são utilizados ou
 *    2. Caso contrário, o IP é utilizado.
 * 
 * Todas as consultas são registradas numa distribuição de probabilidade, onde é
 * possível alternar de HAM para SPAM utilizando o ticket gerado. Uma vez
 * recebida a reclamação com o ticket, o serviço descriptografa o ticket e
 * extrai os responsaveis pelo envio.
 *
 * @author Leandro Carlos Rodrigues <leandro@allchemistry.com.br>
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
        refresh(false);
    }

    /**
     * Consulta o registro SPF nos registros DNS do domínio. Se houver mais de
     * dois registros diferentes, realiza o merge do forma a retornar um único
     * registro.
     *
     * @param hostname o nome do hostname para consulta do SPF.
     * @return o registro SPF consertado, padronuzado e mergeado.
     * @throws ProcessException
     */
    private static LinkedList<String> getRegistrySPF(String hostname) throws ProcessException {
        try {
            LinkedList<String> registryList = new LinkedList<String>();
            if (CacheGuess.contains(hostname)) {
                // Sempre que houver registro de
                // chute, sobrepor registro atual.
                registryList.add(CacheGuess.get(hostname));
            } else {
                // Caso contrário procurar nos
                // registros oficiais do domínio.
                try {
                    Attributes attributes = Server.INITIAL_DIR_CONTEXT.getAttributes(
                            "dns:/" + hostname, new String[]{"SPF"});
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
                        Attributes attributes = Server.INITIAL_DIR_CONTEXT.getAttributes(
                                "dns:/" + hostname, new String[]{"TXT"});
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
            }
            if (registryList.isEmpty()) {
//                hostname = "." + hostname;
//                if (CacheGuess.contains(hostname)) {
//                    // Significa que um palpite SPF
//                    // foi registrado ara este hostname.
//                    // Neste caso utilizar o paltpite.
//                    registryList.add(CacheGuess.get(hostname));
//                } else {
                    // Se não hoouver palpite específico para o hostname,
                    // utilizar o palpite padrão.
                    // http://www.openspf.org/FAQ/Best_guess_record
                    registryList.add(CacheGuess.BEST_GUESS);
//                }
            }
            return registryList;
        } catch (NamingException ex) {
            return null;
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
        registry = registry.replace('\"', ' ');
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
     * Verifica se o token é um mecanismo cental.
     *
     * @param token o token do registro SPF.
     * @return verdadeiro se o token é um mecanismo cental.
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
        // Se procurou 32 vezes seguidas e retornou domínio inexistente,
        // considerar como definitivamente inexistente.
        return nxdomain > 32;
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

    /**
     * Atualiza o registro SPF de um hostname.
     *
     * @throws ProcessException se houver falha no processamento.
     */
    private void refresh(boolean load) throws ProcessException {
        long time = System.currentTimeMillis();
        LinkedList<String> registryList = getRegistrySPF(hostname);
        if (registryList == null) {
            // Domínimo não encontrado.
            this.mechanismList = null;
            this.all = null;
            this.redirect = null;
            this.explanation = null;
            this.error = false;
            CacheSPF.CHANGED = true;
            this.queries = 0;
            this.addInexistent();
            this.lastRefresh = System.currentTimeMillis();
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
            this.lastRefresh = System.currentTimeMillis();
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
                    result = (errorRegistry ? "ERROR" : "OK") + " \"" + registry + "\"";
                } else {
                    result += (errorRegistry ? "\\nERROR" : "\\nOK") + " \"" + registry + "\"";
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
            this.lastRefresh = System.currentTimeMillis();
            Server.logLookupSPF(time, hostname, result);
        }
    }

    /**
     * Verifica se o token é um mecanismo all válido.
     *
     * @param token o token a ser verificado.
     * @return verdadeiro se o token é um mecanismo all válido.
     */
    private static boolean isMechanismAll(String token) {
        return Pattern.matches(
                "^(\\+|-|~|\\?)?all$", token.toLowerCase());
    }

    /**
     * Verifica se o token é um mecanismo ip4 válido.
     *
     * @param token o token a ser verificado.
     * @return verdadeiro se o token é um mecanismo ip4 válido.
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
     * @param token o token a ser verificado.
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
     * Verifica se o token é um mecanismo ip6 válido.
     *
     * @param token o token a ser verificado.
     * @return verdadeiro se o token é um mecanismo ip6 válido.
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
     * @param token o token a ser verificado.
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
        hostname = hostname.replace("%{h}", helo);
        hostname = hostname.replace("%{l}", local);
        hostname = hostname.replace("%{o}", domain);
        hostname = hostname.replace("%{d}", domain);
        hostname = hostname.replace("%{s}", sender);
        hostname = hostname.replace("%{ir}", Subnet.reverse(ip));
        return hostname;
    }

    /**
     * Verifica se o token é um mecanismo a válido.
     *
     * @param token o token a ser verificado.
     * @return verdadeiro se o token é um mecanismo a válido.
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
     * Verifica se o token é um mecanismo mx válido.
     *
     * @param token o token a ser verificado.
     * @return verdadeiro se o token é um mecanismo mx válido.
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
     * Verifica se o token é um mecanismo ptr válido.
     *
     * @param token o token a ser verificado.
     * @return verdadeiro se o token é um mecanismo ptr válido.
     */
    private static boolean isMechanismPTR(String token) {
        token = expand(token, "127.0.0.1", "sender@domain.tld", "host.domain.tld");
        return Pattern.matches(
                "^(\\+|-|~|\\?)?ptr"
                + "(:(?=.{1,255}$)[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?(?:\\.[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?)*\\.?)?"
                + "$", token.toLowerCase());
    }

    /**
     * Verifica se o token é um mecanismo existis válido.
     *
     * @param token o token a ser verificado.
     * @return verdadeiro se o token é um mecanismo existis válido.
     */
    private static boolean isMechanismExistis(String token) {
        token = expand(token, "127.0.0.1", "sender@domain.tld", "host.domain.tld");
        return Pattern.matches(
                "^(\\+|-|~|\\?)?exists:"
                + "((?=.{1,255}$)[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?(?:\\.[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?)*\\.?)"
                + "$", token.toLowerCase());
    }

    /**
     * Verifica se o token é um mecanismo include válido.
     *
     * @param token o token a ser verificado.
     * @return verdadeiro se o token é um mecanismo include válido.
     */
    private static boolean isMechanismInclude(String token) {
        token = expand(token, "127.0.0.1", "sender@domain.tld", "host.domain.tld");
        return Pattern.matches(
                "^(\\+|-|~|\\?)?include:"
                + "(\\.?(?=.{1,255}$)[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?(?:\\.[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?)*\\.?)"
                + "$", token.toLowerCase());
    }

    /**
     * Verifica se o token é um modificador redirect válido.
     *
     * @param token o token a ser verificado.
     * @return verdadeiro se o token é um modificador redirect válido.
     */
    private static boolean isModifierRedirect(String token) {
        return Pattern.matches(
                "^redirect="
                + "((?=.{1,255}$)[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?(?:\\.[0-9A-Za-z_](?:(?:[0-9A-Za-z_]|-){0,61}[0-9A-Za-z_])?)*\\.?)"
                + "$", token.toLowerCase());
    }

    /**
     * Verifica se o token é um modificador explanation válido.
     *
     * @param token o token a ser verificado.
     * @return verdadeiro se o token é um modificador explanation válido.
     */
    private static boolean isModifierExplanation(String token) {
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
     * Retorna o resultado SPF para um IP especifico.
     *
     * @param ip o IP a ser verificado.
     * @return o resultado SPF para um IP especifico.
     * @throws ProcessException se houver falha no processamento.
     */
    public String getResult(String ip, String sender, String helo) throws ProcessException {
        Qualifier qualifier = getQualifier(ip, sender, helo, 0, new TreeSet<String>());
        if (qualifier == null) {
            return "NONE";
        } else {
            return qualifier.name();
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
            int deep, TreeSet<String> hostVisitedSet) throws ProcessException {
        if (deep > 10) {
            return null; // Evita excesso de consultas.
        } else if (hostVisitedSet.contains(getHostname())) {
            return null; // Evita looping infinito.
        } else if (mechanismList == null) {
            throw new ProcessException("ERROR: HOST NOT FOUND");
        } else
//            if (redirect == null)
            {
            hostVisitedSet.add(getHostname());
            for (Mechanism mechanism : mechanismList) {
                if (mechanism instanceof MechanismInclude) {
                    try {
                        MechanismInclude include = (MechanismInclude) mechanism;
                        Qualifier qualifier = include.getQualifierSPF(
                                ip, sender, helo, deep + 1, hostVisitedSet);
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
                        return mechanism.getQualifier();
                    }
                } else if (mechanism.match(ip, sender, helo)) {
                    return mechanism.getQualifier();
                }
            }
            if (redirect != null) {
//                hostVisitedSet.add(getHostname());
                SPF spf = CacheSPF.get(redirect);
                if (spf == null) {
                    return null;
                } else {
                    return spf.getQualifier(ip, sender, helo, 0, hostVisitedSet);
                }
            } else if (error) {
                // Foi encontrado um erro em algum mecanismos
                // na qual os demais não tiveram macth.
                throw new ProcessException("ERROR: SPF PARSE");
            } else if (deep > 0) {
                // O mecanismo all só deve ser
                // processado no primeiro nível da árvore.
                return null;
            } else {
                // Retorna o qualificador do mecanismo all.
                // Pode ser nulo caso o registro não apresente o mecanismo all.
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
                    Attributes attributes = Server.INITIAL_DIR_CONTEXT.getAttributes(
                            "dns:/" + hostname, new String[]{"A", "AAAA"});
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
                    Attribute attributeAAAA = attributes.get("AAAA");
                    if (attributeAAAA != null) {
                        NamingEnumeration enumeration = attributeAAAA.getAll();
                        while (enumeration.hasMoreElements()) {
                            String hostAddress = (String) enumeration.next();
                            int indexSpace = hostAddress.indexOf(' ') + 1;
                            hostAddress = hostAddress.substring(indexSpace);
                            if (!SubnetIPv6.isValidIPv6(hostAddress)) {
                                try {
                                    hostAddress = InetAddress.getByName(hostAddress).getHostAddress();
                                } catch (UnknownHostException ex) {
                                    // Registro AAAA não encontrado.
                                }
                            }
                            if (maskIPv6 != null) {
                                hostAddress += "/" + maskIPv6;
                            }
                            mechanismList.add(new MechanismIPv6(hostAddress));
                            resultSet.add(hostAddress);
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
                    Attributes attributesMX = Server.INITIAL_DIR_CONTEXT.getAttributes(
                            "dns:/" + hostname, new String[]{"MX"});
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
                                    Attributes attributesA = Server.INITIAL_DIR_CONTEXT.getAttributes(
                                            "dns:/" + hostAddress, new String[]{"A", "AAAA"});
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
                                    Attribute attributeAAAA = attributesA.get("AAAA");
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
            int index = expression.indexOf(':') + 1;
            expression = expression.substring(index);
            expression = expand(expression, ip, sender, helo);
            return expression;
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
            Attributes atributes = Server.INITIAL_DIR_CONTEXT.getAttributes(
                    "dns:/" + reverse, new String[]{"PTR"});
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
                        atributes = Server.INITIAL_DIR_CONTEXT.getAttributes(
                                "dns:/" + host, new String[]{"A"});
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
                        atributes = Server.INITIAL_DIR_CONTEXT.getAttributes(
                                "dns:/" + host, new String[]{"AAAA"});
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
                Server.INITIAL_DIR_CONTEXT.getAttributes(
                        "dns:/" + hostname, new String[]{"A","AAAA"});
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

        public Qualifier getQualifierSPF(
                String ip, String sender, String helo,
                int deep, TreeSet<String> hostVisitedSet) throws ProcessException {
            String hostname = getHostname(ip, sender, helo);
            SPF spf = CacheSPF.get(hostname);
            if (spf == null) {
                return null;
            } else {
                return spf.getQualifier(ip, sender, helo, deep, hostVisitedSet);
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
        private static final HashMap<String, SPF> MAP = new HashMap<String, SPF>();
        /**
         * Flag que indica se o cache foi modificado.
         */
        private static boolean CHANGED = false;

        /**
         * Adiciona um registro SPF no mapa de cache.
         *
         * @param spf o registro SPF para ser adocionado.
         */
        private static synchronized void add(SPF spf) {
            MAP.put(spf.getHostname(), spf);
            CHANGED = true;
        }
        
        public static boolean refresh(String address,
                boolean load) throws ProcessException {
            String host = Domain.extractHost(address, false);
            if (host == null) {
                return false;
            } else {
                SPF spf = MAP.get(host);
                if (spf == null) {
                    return false;
                } else {
                    spf.refresh(load);
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
        public static SPF get(String address) throws ProcessException {
            String host = Domain.extractHost(address, false);
            if (host == null) {
                return null;
            } else {
                SPF spf = MAP.get(host);
                if (spf == null) {
                    spf = new SPF(host);
                    add(spf);
                } else {
                    if (spf.isRegistryExpired()) {
                        // Atualiza o registro se ele for antigo demais.
                        spf.refresh(false);
                    }
                }
                spf.queries++; // Incrementa o contador de consultas.
                return spf;
            }
        }

        private static synchronized void remove(String host) {
            if (MAP.remove(host) != null) {
                CHANGED = true;
            }
        }

        private static synchronized void store() {
            if (CHANGED) {
                try {
                    long time = System.currentTimeMillis();
                    File file = new File("spf.map");
                    FileOutputStream outputStream = new FileOutputStream(file);
                    try {
                        SerializationUtils.serialize(MAP, outputStream);
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

        private static synchronized void load() {
            long time = System.currentTimeMillis();
            File file = new File("spf.map");
            if (file.exists()) {
                try {
                    HashMap<String, SPF> map;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        map = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    MAP.putAll(map);
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
            SPF spfMax = null;
            for (SPF spf : MAP.values()) {
                if (spfMax == null) {
                    spfMax = spf;
                } else if (spfMax.queries < spf.queries) {
                    spfMax = spf;
                }
            }
            if (spfMax != null && spfMax.queries > 3) {
                try {
                    spfMax.refresh(true);
                } catch (ProcessException ex) {
                    if (ex.getMessage().equals("ERROR: HOST NOT FOUND")) {
                        Server.logDebug(spfMax.getHostname() + ": SPF registry cache removed.");
                    } else {
                        Server.logError(ex);
                    }
                }
            }
            store();
        }
    }
    private static final Semaphore REFRESH_SEMAPHORE = new Semaphore(1);

    /**
     * Atualiza registros SPF somente se nenhum outro processo estiver
     * atualizando.
     */
    public static void tryRefresh() {
        // Evita que muitos processos fiquem
        // presos aguardando a liberação do método.
        if (REFRESH_SEMAPHORE.tryAcquire()) {
            try {
                CacheSPF.refresh();
                CacheHELO.refresh();
            } finally {
                REFRESH_SEMAPHORE.release();
            }
        }
    }

    /**
     * Classe que representa o cache de registros de denúncia.
     */
    private static class CacheComplain {

        /**
         * Mapa de reclamações com seus respectivos tickets.
         */
        private static final HashMap<String, Complain> MAP = new HashMap<String, Complain>();
        /**
         * Flag que indica se o cache de reclamações foi modificado.
         */
        private static boolean CHANGED = false;

        private static synchronized void store() {
            if (CHANGED) {
                try {
                    long time = System.currentTimeMillis();
                    File file = new File("complain.map");
                    FileOutputStream outputStream = new FileOutputStream(file);
                    try {
                        SerializationUtils.serialize(MAP, outputStream);
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

        private static synchronized void load() {
            long time = System.currentTimeMillis();
            File file = new File("complain.map");
            if (file.exists()) {
                try {
                    HashMap<String, Complain> map;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        map = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    MAP.putAll(map);
                    Server.logLoad(time, file);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }

        private static synchronized HashMap<String,Complain> get() {
            HashMap<String,Complain> complainMap = new HashMap<String,Complain>();
            complainMap.putAll(MAP);
            return complainMap;
        }

        private static synchronized boolean drop(String ticket) {
            if (MAP.remove(ticket) == null) {
                return false;
            } else {
                CHANGED = true;
                return true;
            }
        }

        /**
         * Timer que controla as reclamações.
         */
        private static final Timer TIMER = new Timer("TimerComplain");

        public static void cancel() {
            TIMER.cancel();
        }

        static {
            // Agenda processamento de reclamações vencidas.
            TIMER.schedule(
                    new TimerTask() {
                @Override
                public void run() {
                    LinkedList<String> expiredTicket = new LinkedList<String>();
                    // Verificar reclamações vencidas.
                    HashMap<String,Complain> complainMap = get();
                    for (String ticket : complainMap.keySet()) {
                        Complain complain = complainMap.get(ticket);
                        if (complain.isExpired7()) {
                            complain.removeComplains();
                            expiredTicket.add(ticket);
                        }
                    }
                    // Remover todos os tickets processados.
                    for (String ticket : expiredTicket) {
                        drop(ticket);
                    }
                    // Apagar todas as distribuições vencidas.
                    CacheDistribution.dropExpired();
                    // Apagar todas os registros de DNS de HELO vencidos.
                    CacheHELO.dropExpired();
                }
            }, 3600000, 3600000 // Frequência de 1 hora.
                    );
        }

        /**
         * Adiciona uma nova reclamação de SPAM.
         *
         * @param ticket o ticket da mensagem original.
         * @throws ProcessException se houver falha no processamento do ticket.
         */
        public synchronized static TreeSet<String> add(String ticket) throws ProcessException {
            if (MAP.containsKey(ticket)) {
                return null;
            } else {
                Complain complain = new Complain(ticket);
                MAP.put(ticket, complain);
                CHANGED = true;
                return complain.getTokenSet();
            }
        }

        /**
         * Remove uma nova reclamação de SPAM.
         *
         * @param ticket o ticket da mensagem original.
         * @throws ProcessException se houver falha no processamento do ticket.
         */
        public synchronized static TreeSet<String> remove(String ticket) {
            Complain complain = MAP.remove(ticket);
            if (complain == null) {
                return null;
            } else {
                complain.removeComplains();
                CHANGED = true;
                return complain.getTokenSet();
            }
        }
    }

    public static void cancel() {
        CacheComplain.cancel();
    }

    /**
     * Classe que representa o cache de registros de distribuição de
     * responsáveis.
     */
    private static class CacheDistribution {

        /**
         * Mapa de distribuição binomial dos tokens encontrados.
         */
        private static final HashMap<String, Distribution> MAP = new HashMap<String, Distribution>();
        /**
         * Flag que indica se o cache foi modificado.
         */
        private static boolean CHANGED = false;

        private static synchronized void store() {
            if (CHANGED) {
                try {
                    long time = System.currentTimeMillis();
                    File file = new File("distribution.map");
                    FileOutputStream outputStream = new FileOutputStream(file);
                    try {
                        SerializationUtils.serialize(MAP, outputStream);
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

        private static synchronized void load() {
            long time = System.currentTimeMillis();
            File file = new File("distribution.map");
            if (file.exists()) {
                try {
                    HashMap<String, Distribution> map;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        map = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    MAP.putAll(map);
                    Server.logLoad(time, file);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }

        public static void dropExpired() {
            TreeSet<String> distributionKeySet = new TreeSet<String>();
            distributionKeySet.addAll(MAP.keySet());
            for (String token : distributionKeySet) {
                Distribution distribution = MAP.get(token);
                if (distribution != null
                        && distribution.hasLastQuery()
                        && distribution.isExpired14()) {
                    drop(token);
                }
            }
        }

        public static synchronized void drop(String token) {
            if (MAP.remove(token) != null) {
                CacheBlock.dropExact(token);
                CHANGED = true;
            }
        }

        public static synchronized void put(String token,
                Distribution distribution) {
            if (MAP.put(token, distribution) == null) {
                CHANGED = true;
            }
        }

        /**
         * Retorna uma distribuição binomial do token informado.
         *
         * @param token o token cuja distribuição deve ser retornada.
         * @return uma distribuição binomial do token informado.
         */
        private static Distribution get(String token, boolean create) {
            Distribution distribution = MAP.get(token);
            if (distribution != null) {
                if (distribution.isExpired7()) {
                    distribution.reset();
                }
            } else if (create) {
                distribution = new Distribution();
                put(token, distribution);
            } else {
                distribution = null;
            }
            return distribution;
        }

        public static TreeMap<String, Distribution> getMap() {
            TreeMap<String, Distribution> distributionMap = new TreeMap<String, Distribution>();
            distributionMap.putAll(MAP);
            return distributionMap;
        }

        public static TreeMap<String, Distribution> getMap(TreeSet<String> tokenSet) {
            TreeMap<String, Distribution> distributionMap = new TreeMap<String, Distribution>();
            for (String token : tokenSet) {
                Distribution distribution = MAP.get(token);
                if (distribution != null) {
                    distributionMap.put(token, distribution);
                }
            }
            return distributionMap;
        }
    }

    public static TreeMap<String, Distribution> getDistributionMap() {
        return CacheDistribution.getMap();
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

        public static synchronized boolean add(String domain) throws ProcessException {
            domain = Domain.extractHost(domain, false);
            if (!Domain.containsDomain(domain)) {
                throw new ProcessException("ERROR: PROVIDER INVALID");
            } else {
                domain = "@" + domain;
                if (SET.add(domain)) {
                    CHANGED = true;
                    return true;
                } else {
                    return false;
                }
            }
        }

        public static synchronized boolean drop(String domain) throws ProcessException {
            domain = Domain.extractHost(domain, false);
            if (!Domain.containsDomain(domain)) {
                throw new ProcessException("ERROR: PROVIDER INVALID");
            } else {
                domain = "@" + domain;
                if (SET.remove(domain)) {
                    CHANGED = true;
                    return true;
                } else {
                    return false;
                }
            }
        }

        public static boolean contains(String host) {
            return SET.contains(host);
        }

        public static synchronized TreeSet<String> get() throws ProcessException {
            TreeSet<String> blockSet = new TreeSet<String>();
            blockSet.addAll(SET);
            return blockSet;
        }

        private static synchronized void store() {
            if (CHANGED) {
                try {
                    long time = System.currentTimeMillis();
                    File file = new File("provider.set");
                    FileOutputStream outputStream = new FileOutputStream(file);
                    try {
                        SerializationUtils.serialize(SET, outputStream);
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

        private static synchronized void load() {
            long time = System.currentTimeMillis();
            File file = new File("provider.set");
            if (file.exists()) {
                try {
                    TreeSet<String> set;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        set = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    SET.addAll(set);
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
        private static final HashSet<String> SET = new HashSet<String>();
        /**
         * Flag que indica se o cache foi modificado.
         */
        private static boolean CHANGED = false;

        private static boolean isValid(String sender) {
            if (sender == null) {
                return false;
            } else if (Domain.isEmail(sender)) {
                return true;
            } else if (sender.startsWith("@") && Domain.containsDomain(sender.substring(1))) {
                return true;
            } else if (sender.startsWith(".") && Domain.containsDomain(sender.substring(1))) {
                return true;
            } else {
                return false;
            }
        }

        public static synchronized boolean add(String sender) throws ProcessException {
            if (!isValid(sender)) {
                throw new ProcessException("ERROR: SENDER INVALID");
            } else if (SET.add(sender.toLowerCase())) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }

        public static synchronized boolean add(String client, String sender) throws ProcessException {
            if (client == null) {
                throw new ProcessException("ERROR: CLIENT INVALID");
            } else if (!isValid(sender)) {
                throw new ProcessException("ERROR: SENDER INVALID");
            } else if (SET.add(client + ':' + sender.toLowerCase())) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }

        public static synchronized boolean drop(String sender) throws ProcessException {
            if (!isValid(sender)) {
                throw new ProcessException("ERROR: SENDER INVALID");
            } else if (SET.remove(sender.toLowerCase())) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }

        public static synchronized boolean drop(String client, String sender) throws ProcessException {
            if (client == null) {
                throw new ProcessException("ERROR: CLIENT INVALID");
            } else if (!isValid(sender)) {
                throw new ProcessException("ERROR: SENDER INVALID");
            } else if (SET.remove(client + ':' + sender.toLowerCase())) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }

        public static synchronized TreeSet<String> get(String client) throws ProcessException {
            TreeSet<String> whiteSet = new TreeSet<String>();
            for (String sender : SET) {
                if (sender.startsWith(client + ':')) {
                    int index = sender.indexOf(':') + 1;
                    sender = sender.substring(index);
                    whiteSet.add(sender);
                }
            }
            return whiteSet;
        }

        public static boolean contains(String client, String sender) {
            if (client == null) {
                return false;
            } else if (!isValid(sender)) {
                return false;
            } else {
                sender = sender.toLowerCase();
                int index2 = sender.lastIndexOf('@');
                String domain = sender.substring(index2);
                if (SET.contains(sender)) {
                    return true;
                } else if (SET.contains(domain)) {
                    return true;
                } else if (SET.contains(client + ':' + sender)) {
                    return true;
                } else if (SET.contains(client + ':' + domain)) {
                    return true;
                } else if (containsHost(client, domain.substring(1))) {
                    return true;
                } else {
                    int index3 = domain.length();
                    while ((index3 = domain.lastIndexOf('.', index3-1)) > index2) {
                        String subdomain = domain.substring(0, index3 + 1);
                        if (SET.contains(subdomain)) {
                            return true;
                        } else if (SET.contains(client + ':' + subdomain)) {
                            return true;
                        }
                    }
                    int index4 = sender.length();
                    while ((index4 = sender.lastIndexOf('.', index4-1)) > index2) {
                        String subsender = sender.substring(0, index4 + 1);
                        if (SET.contains(subsender)) {
                            return true;
                        } else if (SET.contains(client + ':' + subsender)) {
                            return true;
                        }
                    }
                    return false;
                }
            }
        }

        private static boolean containsHost(String client, String host) {
            do {
                int index = host.indexOf('.') + 1;
                host = host.substring(index);
                String token = '.' + host;
                if (SET.contains(token)) {
                    return true;
                } else if (SET.contains(client + ':' + token)) {
                    return true;
                }
            } while (host.contains("."));
            return false;
        }

        private static synchronized void store() {
            if (CHANGED) {
                try {
                    long time = System.currentTimeMillis();
                    File file = new File("white.set");
                    FileOutputStream outputStream = new FileOutputStream(file);
                    try {
                        SerializationUtils.serialize(SET, outputStream);
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

        private static synchronized void load() {
            long time = System.currentTimeMillis();
            File file = new File("white.set");
            if (file.exists()) {
                try {
                    Set<String> set;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        set = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    SET.addAll(set);
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

    public static boolean dropWhite(String sender) throws ProcessException {
        return CacheWhite.drop(sender);
    }

    public static boolean dropWhite(String client, String sender) throws ProcessException {
        return CacheWhite.drop(client, sender);
    }

    public static TreeSet<String> getWhiteSet(String client) throws ProcessException {
        return CacheWhite.get(client);
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

        public static synchronized boolean add(String recipient) throws ProcessException {
            if (!isValid(recipient)) {
                throw new ProcessException("ERROR: RECIPIENT INVALID");
            } else if (SET.add(recipient.toLowerCase())) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }

        public static synchronized boolean add(String client, String recipient) throws ProcessException {
            if (client == null) {
                throw new ProcessException("ERROR: CLIENT INVALID");
            } else if (!isValid(recipient)) {
                throw new ProcessException("ERROR: RECIPIENT INVALID");
            } else if (SET.add(client + ':' + recipient.toLowerCase())) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }

        public static synchronized boolean drop(String recipient) throws ProcessException {
            if (!isValid(recipient)) {
                throw new ProcessException("ERROR: RECIPIENT INVALID");
            } else if (SET.remove(recipient.toLowerCase())) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }

        public static synchronized boolean drop(String client, String recipient) throws ProcessException {
            if (client == null) {
                throw new ProcessException("ERROR: CLIENT INVALID");
            } else if (!isValid(recipient)) {
                throw new ProcessException("ERROR: RECIPIENT INVALID");
            } else if (SET.remove(client + ':' + recipient.toLowerCase())) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }

        public static synchronized TreeSet<String> get(String client) throws ProcessException {
            TreeSet<String> trapSet = new TreeSet<String>();
            for (String recipient : SET) {
                if (recipient.startsWith(client + ':')) {
                    int index = recipient.indexOf(':') + 1;
                    recipient = recipient.substring(index);
                    trapSet.add(recipient);
                }
            }
            return trapSet;
        }

        public static boolean contains(String client, String recipient) {
            if (client == null) {
                return false;
            } else if (!isValid(recipient)) {
                return false;
            } else {
                recipient = recipient.toLowerCase();
                int index2 = recipient.lastIndexOf('@');
                String domain = recipient.substring(recipient.lastIndexOf('@'));
                if (SET.contains(recipient)) {
                    return true;
                } else if (SET.contains(domain)) {
                    return true;
                } else if (SET.contains(client + ':' + recipient)) {
                    return true;
                } else if (SET.contains(client + ':' + domain)) {
                    return true;
                } else {
                    int index3 = domain.length();
                    while ((index3 = domain.lastIndexOf('.', index3-1)) > index2) {
                        String subdomain = domain.substring(0, index3 + 1);
                        if (SET.contains(subdomain)) {
                            return true;
                        } else if (SET.contains(client + ':' + subdomain)) {
                            return true;
                        }
                    }
                    int index4 = recipient.length();
                    while ((index4 = recipient.lastIndexOf('.', index4-1)) > index2) {
                        String subrecipient = recipient.substring(0, index4 + 1);
                        if (SET.contains(subrecipient)) {
                            return true;
                        } else if (SET.contains(client + ':' + subrecipient)) {
                            return true;
                        }
                    }
                    return false;
                }
            }
        }

        private static synchronized void store() {
            if (CHANGED) {
                try {
                    long time = System.currentTimeMillis();
                    File file = new File("trap.set");
                    FileOutputStream outputStream = new FileOutputStream(file);
                    try {
                        SerializationUtils.serialize(SET, outputStream);
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

        private static synchronized void load() {
            long time = System.currentTimeMillis();
            File file = new File("trap.set");
            if (file.exists()) {
                try {
                    Set<String> set;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        set = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    SET.addAll(set);
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

    public static boolean dropTrap(String sender) throws ProcessException {
        return CacheTrap.drop(sender);
    }

    public static boolean dropTrap(String client, String sender) throws ProcessException {
        return CacheTrap.drop(client, sender);
    }

    public static TreeSet<String> getTrapSet(String client) throws ProcessException {
        return CacheTrap.get(client);
    }

    /**
     * Classe que representa o cache de bloqueios de remetente.
     */
    private static class CacheBlock {

        /**
         * Conjunto de remetentes bloqueados.
         */
        private static final HashSet<String> SET = new HashSet<String>();
        /**
         * Flag que indica se o cache foi modificado.
         */
        private static boolean CHANGED = false;

        public static synchronized boolean add(String token) throws ProcessException {
            if ((token = normalizeToken(token)) == null) {
                throw new ProcessException("ERROR: TOKEN INVALID");
            } else if (SET.add(token.toLowerCase())) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }

        public static synchronized boolean addAndDisseminate(String token) {
            if (token == null) {
                return false;
            } else if (SET.add(token)) {
                // Disseminar informação via P2P.
                CachePeer.send(token);
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }

        public static synchronized boolean add(String client, String token) throws ProcessException {
            if (client == null) {
                throw new ProcessException("ERROR: CLIENT INVALID");
            } else if ((token = normalizeToken(token)) == null) {
                throw new ProcessException("ERROR: TOKEN INVALID");
            } else if (SET.add(client + ':' + token)) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }

        public static String normalizeToken(String token) throws ProcessException {
            String qualif;
            if (token == null) {
                return null;
            } else if (token.contains(";")) {
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
                } else {
                    // Sintaxe com erro.
                    return null;
                }
            } else {
                qualif = "";
            }
            if (Owner.isOwnerID(token)) {
                return Owner.normalizeID(token) + qualif;
            } else if (Domain.isEmail(token)) {
                return token.toLowerCase() + qualif;
            } else if (token.endsWith("@")) {
                return token.toLowerCase() + qualif;
            } else if (token.startsWith("@") && Domain.containsDomain(token.substring(1))) {
                return token.toLowerCase() + qualif;
            } else if (!token.contains("@") && Domain.containsDomain(token)) {
                return Domain.extractHost(token, true) + qualif;
            } else if (token.startsWith(".") && Domain.containsDomain(token.substring(1))) {
                return Domain.extractHost(token, true) + qualif;
            } else if (Subnet.isValidIP(token)) {
                return Subnet.normalizeIP(token) + qualif;
            } else if (Subnet.isValidCIDR(token)) {
                return Subnet.normalizeCIDR(token) + qualif;
            } else {
                return null;
            }
        }

        public static synchronized boolean drop(String token) throws ProcessException {
            if ((token = normalizeToken(token)) == null) {
                throw new ProcessException("ERROR: TOKEN INVALID");
            } else if (SET.remove(token)) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }

        public static synchronized boolean dropExact(String token) {
            if (SET.remove(token)) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }

        public static synchronized boolean drop(String client, String token) throws ProcessException {
            if (client == null) {
                throw new ProcessException("ERROR: CLIENT INVALID");
            } else if ((token = normalizeToken(token)) == null) {
                throw new ProcessException("ERROR: TOKEN INVALID");
            } else if (SET.remove(client + ':' + token)) {
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }

        public static synchronized TreeSet<String> get(String client) throws ProcessException {
            TreeSet<String> blockSet = new TreeSet<String>();
            for (String token : SET) {
                if (token.startsWith(client + ':')) {
                    int index = token.indexOf(':') + 1;
                    token = token.substring(index);
                    blockSet.add(token);
                }
            }
            return blockSet;
        }

        public static synchronized TreeSet<String> get() throws ProcessException {
            TreeSet<String> blockSet = new TreeSet<String>();
            for (String token : SET) {
                if (!token.contains(":")) {
                    blockSet.add(token);
                }
            }
            return blockSet;
        }

        public static synchronized TreeSet<String> getAll() throws ProcessException {
            TreeSet<String> blockSet = new TreeSet<String>();
            blockSet.addAll(SET);
            return blockSet;
        }

        public static boolean contains(String client,
                String ip, String sender, String helo,
                String ownerid, String qualifier) {
            if (sender != null && sender.contains("@")) {
                sender = sender.toLowerCase();
                int index1 = sender.indexOf('@');
                int index2 = sender.lastIndexOf('@');
                String part = sender.substring(0, index1 + 1);
                String domain = sender.substring(index2);
                if (SET.contains(sender)) {
                    return true;
                } else if (SET.contains(sender + ';' + qualifier)) {
                    return true;
                } else if (SET.contains(client + ':' + sender)) {
                    return true;
                } else if (SET.contains(client + ':' + sender + ';' + qualifier)) {
                    return true;
                } else if (SET.contains(part)) {
                    return true;
                } else if (SET.contains(part + ';' + qualifier)) {
                    return true;
                } else if (SET.contains(client + ':' + part)) {
                    return true;
                } else if (SET.contains(client + ':' + part + ';' + qualifier)) {
                    return true;
                } else if (SET.contains(domain)) {
                    return true;
                } else if (SET.contains(domain + ';' + qualifier)) {
                    return true;
                } else if (SET.contains(client + ':' + domain)) {
                    return true;
                } else if (SET.contains(client + ':' + domain + ';' + qualifier)) {
                    return true;
                } else if (containsHost(client, domain.substring(1), qualifier)) {
                    return true;
                } else {
                    int index3 = domain.length();
                    while ((index3 = domain.lastIndexOf('.', index3-1)) > index2) {
                        String subdomain = domain.substring(0, index3 + 1);
                        if (SET.contains(subdomain)) {
                            return true;
                        } else if (SET.contains(subdomain + ';' + qualifier)) {
                            return true;
                        } else if (SET.contains(client + ':' + subdomain)) {
                            return true;
                        } else if (SET.contains(client + ':' + subdomain + ';' + qualifier)) {
                            return true;
                        }
                    }
                    int index4 = sender.length();
                    while ((index4 = sender.lastIndexOf('.', index4-1)) > index2) {
                        String subsender = sender.substring(0, index4 + 1);
                        if (SET.contains(subsender)) {
                            return true;
                        } else if (SET.contains(subsender + ';' + qualifier)) {
                            return true;
                        } else if (SET.contains(client + ':' + subsender)) {
                            return true;
                        } else if (SET.contains(client + ':' + subsender + ';' + qualifier)) {
                            return true;
                        }
                    }
                }
            }
            if ((helo = Domain.extractHost(helo, true)) != null) {
                if (containsHost(client, helo, qualifier)) {
                    return true;
                }
            }
            if (ownerid != null) {
                if (SET.contains(ownerid)) {
                    return true;
                } else if (SET.contains(ownerid + ';' + qualifier)) {
                    return true;
                } else if (SET.contains(client + ':' + ownerid)) {
                    return true;
                } else if (SET.contains(client + ':' + ownerid + ';' + qualifier)) {
                    return true;
                }
            }
            if (ip != null) {
                ip = Subnet.normalizeIP(ip);
                if (SET.contains(ip)) {
                    return true;
                } else if (SET.contains(ip + ';' + qualifier)) {
                    return true;
                } else if (SET.contains(client + ':' + ip)) {
                    return true;
                } else if (SET.contains(client + ':' + ip + ';' + qualifier)) {
                    return true;
                }
                String inet = Subnet.getInetnum(ip);
                if (inet != null) {
                    if (SET.contains(inet)) {
                        return true;
                    } else if (SET.contains(inet + ';' + qualifier)) {
                        return true;
                    } else if (SET.contains(client + ':' + inet)) {
                        return true;
                    } else if (SET.contains(client + ':' + inet + ';' + qualifier)) {
                        return true;
                    }
                }
            }
            return false;
        }

        private static boolean containsHost(String client, String host, String qualifier) {
            do {
                int index = host.indexOf('.') + 1;
                host = host.substring(index);
                String token = '.' + host;
                if (SET.contains(token)) {
                    return true;
                } else if (SET.contains(token + ';' + qualifier)) {
                    return true;
                } else if (SET.contains(client + ':' + token)) {
                    return true;
                } else if (SET.contains(client + ':' + token + ';' + qualifier)) {
                    return true;
                }
            } while (host.contains("."));
            return false;
        }

        private static synchronized void store() {
            if (CHANGED) {
                try {
                    long time = System.currentTimeMillis();
                    File file = new File("block.set");
                    FileOutputStream outputStream = new FileOutputStream(file);
                    try {
                        SerializationUtils.serialize(SET, outputStream);
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

        private static synchronized void load() {
            long time = System.currentTimeMillis();
            File file = new File("block.set");
            if (file.exists()) {
                try {
                    Set<String> set;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        set = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    SET.addAll(set);
                    Server.logLoad(time, file);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }
    }

    public static void main(String[] args) {
        try {
//            String ip = "200.160.2.5";
            String ip = "2001:12ff:0:2::5";
            String sender = "remetente@registro.br";
            String helo = "mailx.registro.br";
            SPF spf = CacheSPF.get("registro.br");
            for (Mechanism mechamism : spf.mechanismList) {
                if (mechamism instanceof MechanismA) {
                    MechanismA mechanismA = (MechanismA) mechamism;
                    System.out.println(mechanismA.match(ip, sender, helo));
                } else if (mechamism instanceof MechanismMX) {
                    MechanismMX mechanismMX = (MechanismMX) mechamism;
                    System.out.println(mechanismMX.match(ip, sender, helo));
                }
            }
            System.out.println(spf);
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
            System.exit(0);
        }
    }

    public static boolean addBlock(String sender) throws ProcessException {
        return CacheBlock.add(sender);
    }

    public static boolean addBlock(String client, String sender) throws ProcessException {
        return CacheBlock.add(client, sender);
    }

    public static boolean dropBlock(String sender) throws ProcessException {
        return CacheBlock.drop(sender);
    }

    public static boolean dropBlock(String client, String sender) throws ProcessException {
        return CacheBlock.drop(client, sender);
    }

    public static TreeSet<String> getBlockSet(String client) throws ProcessException {
        return CacheBlock.get(client);
    }

    public static TreeSet<String> getProviderSet() throws ProcessException {
        return CacheProvider.get();
    }

    public static TreeSet<String> getBlockSet() throws ProcessException {
        return CacheBlock.get();
    }

    public static TreeSet<String> getAllBlockSet() throws ProcessException {
        return CacheBlock.getAll();
    }

    public static boolean clear(String token) {
        Distribution distribution = CacheDistribution.get(token, false);
        if (distribution == null) {
            return false;
        } else if (distribution.clear()) {
            CacheBlock.dropExact(token);
            return true;
        } else {
            return false;
        }
    }

    /**
     * Classe que representa o cache de peers que serão atualizados.
     */
    private static class CachePeer {

        /**
         * Mapa de registros de peers <endereço,porta>.
         */
        private static final HashMap<InetAddress,Integer> MAP = new HashMap<InetAddress,Integer>();

        /**
         * Flag que indica se o cache foi modificado.
         */
        private static boolean CHANGED = false;

        public static synchronized void send(String token) {
            for (InetAddress address : MAP.keySet()) {
                long time = System.currentTimeMillis();
                int port = MAP.get(address);
                String result;
                try {
                    Main.sendTokenToPeer(token, address, port);
                    result = "OK";
                } catch (ProcessException ex) {
                    result = ex.getMessage();
                }
                Server.logPeerSend(time, address, token, result);
            }
        }

        public static synchronized boolean add(String address,
                String port) throws ProcessException {
            try {
                int portInt = Integer.parseInt(port);
                return add(address, portInt);
            } catch (NumberFormatException ex) {
                throw new ProcessException("ERROR: PEER PORT INVALID", ex);
            }
        }

        public static synchronized boolean add(String address,
                Integer port) throws ProcessException {
            try {
                InetAddress inetAddress = InetAddress.getByName(address);
                if (port == null || port < 1 || port > 65535) {
                    throw new ProcessException("ERROR: PEER PORT INVALID");
                } else if (!port.equals(MAP.put(inetAddress, port))) {
                    CHANGED = true;
                    // Enviar imediatamente todos os
                    // tokens bloqueados na base atual.
                    TreeMap<String,Distribution> distributionSet =
                            CacheDistribution.getMap();
                    for (String token : distributionSet.keySet()) {
                        Distribution distribution = distributionSet.get(token);
                        if (distribution.isBlocked(token)) {
                            long time = System.currentTimeMillis();
                            String result;
                            try {
                                Main.sendTokenToPeer(token, inetAddress, port);
                                result = "OK";
                            } catch (ProcessException ex) {
                                result = ex.toString();
                            }
                            Server.logPeerSend(time, inetAddress, token, result);
                        }
                    }
                    return true;
                }
                return false;
            } catch (UnknownHostException ex) {
                throw new ProcessException("ERROR: PEER ADDRESS INVALID", ex);
            }
        }

        public static synchronized boolean drop(
                String address) throws ProcessException {
            try {
                InetAddress inetAddress = InetAddress.getByName(address);
                if (MAP.remove(inetAddress) == null) {
                    return false;
                } else {
                    CHANGED = true;
                    return true;
                }
            } catch (UnknownHostException ex) {
                throw new ProcessException("ERROR: PEER ADDRESS INVALID", ex);
            }
        }

        public static synchronized TreeSet<String> get() throws ProcessException {
            TreeSet<String> blockSet = new TreeSet<String>();
            for (InetAddress inetAddress : MAP.keySet()) {
                int port = MAP.get(inetAddress);
                String result = inetAddress + ":" + port;
                blockSet.add(result);
            }
            return blockSet;
        }

        private static synchronized void store() {
            if (CHANGED) {
                try {
                    long time = System.currentTimeMillis();
                    File file = new File("peer.map");
                    FileOutputStream outputStream = new FileOutputStream(file);
                    try {
                        SerializationUtils.serialize(MAP, outputStream);
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

        private static synchronized void load() {
            long time = System.currentTimeMillis();
            File file = new File("peer.map");
            if (file.exists()) {
                try {
                    HashMap<InetAddress,Integer> map;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        map = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    MAP.putAll(map);
                    Server.logLoad(time, file);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }
    }

    public static boolean addPeer(String address, int port) throws ProcessException {
        return CachePeer.add(address, port);
    }

    public static boolean addPeer(String address, String port) throws ProcessException {
        return CachePeer.add(address, port);
    }

    public static boolean dropPeer(String address) throws ProcessException {
        return CachePeer.drop(address);
    }

    public static TreeSet<String> getPeerSet() throws ProcessException {
        return CachePeer.get();
    }

    public static TreeSet<String> getGuessSet() throws ProcessException {
        return CacheGuess.get();
    }

    /**
     * Classe que representa o cache de "best-guess" exclusivos.
     */
    private static class CacheGuess {

        /**
         * http://www.openspf.org/FAQ/Best_guess_record
         * porém compatível com IPv6
         */
        private static final String BEST_GUESS = "v=spf1 a/24//48 mx/24//48 ptr ?all";
        /**
         * Mapa de registros manuais de SPF caso o domínio não tenha um.
         */
        private static final HashMap<String, String> MAP = new HashMap<String, String>();
        /**
         * Flag que indica se o cache foi modificado.
         */
        private static boolean CHANGED = false;

        public static synchronized boolean add(String hostname,
                String spf) throws ProcessException {
            hostname = Domain.extractHost(hostname, false);
            if (!Domain.containsDomain(hostname)) {
                throw new ProcessException("ERROR: HOSTNAME INVALID");
            } else if (!spf.equals(MAP.put("." + hostname, spf))) {
                CacheSPF.refresh(hostname, true);
                CHANGED = true;
                return true;
            } else {
                return false;
            }
        }

        public static synchronized boolean drop(
                String hostname) throws ProcessException {
            hostname = Domain.extractHost(hostname, false);
            if (!Domain.containsDomain(hostname)) {
                throw new ProcessException("ERROR: HOSTNAME INVALID");
            } else if (MAP.remove("." + hostname) == null) {
                return false;
            } else {
                CacheSPF.refresh(hostname, true);
                CHANGED = true;
                return true;
            }
        }

        public static boolean contains(String host) {
            if (!host.startsWith(".")) {
                host = "." + host;
            }
            return MAP.containsKey(host);
        }

        public static TreeSet<String> get() {
            TreeSet<String> guessSet = new TreeSet<String>();
            for (String domain : MAP.keySet()) {
                String spf = MAP.get(domain);
                guessSet.add(domain + " \"" + spf + "\"");
            }
            return guessSet;
        }

        public static String get(String host) {
            if (!host.startsWith(".")) {
                host = "." + host;
            }
            return MAP.get(host);
        }

        private static synchronized void store() {
            if (CHANGED) {
                try {
                    long time = System.currentTimeMillis();
                    File file = new File("guess.map");
                    FileOutputStream outputStream = new FileOutputStream(file);
                    try {
                        SerializationUtils.serialize(MAP, outputStream);
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

        private static synchronized void load() {
            long time = System.currentTimeMillis();
            File file = new File("guess.map");
            if (file.exists()) {
                try {
                    HashMap<String, String> map;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        map = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    MAP.putAll(map);
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

    public static void storeProvider() {
        CacheProvider.store();
    }

    public static void storeBlock() {
        CacheBlock.store();
    }

    public static void storeGuess() {
        CacheGuess.store();
    }

    public static void storePeer() {
        CachePeer.store();
    }

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
        CacheBlock.store();
        CacheGuess.store();
        CacheHELO.store();
        CachePeer.store();
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
        CacheBlock.load();
        CacheGuess.load();
        CacheHELO.load();
        CachePeer.load();
    }

    /**
     * Classe que representa o cache de resolução de HELO. Na ultima verificação
     * dos registros do LOG foi visto que diversas consultas SPFBL demoram
     * excessivamente por conta da verificação de HELO na qual não existe
     * domínio ou registro para IPs, acarretanto TIMEOUT 3 segundos depois.
     */
    private static class CacheHELO {

        /**
         * Mapa de atributos da verificação de HELO.
         */
        private static final HashMap<String, HELO> MAP = new HashMap<String, HELO>();
        /**
         * Flag que indica se o cache foi modificado.
         */
        private static boolean CHANGED = false;

        /*
         * Classe para guardar os atributos da consulta.
         */
        private static final class HELO implements Serializable {

            private static final long serialVersionUID = 1L;
            private Attributes attributes = null;
            private int queryCount = 0;
            private long lastQuery;

            private HELO(String hostname) throws NamingException {
                this.lastQuery = System.currentTimeMillis();
                refresh(hostname);
            }

            public synchronized void refresh(String hostname) throws NamingException {
                long time = System.currentTimeMillis();
                try {
                    this.attributes = Server.INITIAL_DIR_CONTEXT.getAttributes(
                            "dns:/" + hostname, new String[]{"A", "AAAA"});
                    this.queryCount = 0;
                    CHANGED = true;
                    if (attributes == null) {
                        Server.logLookupHELO(time, hostname, "NXDOMAIN");
                    } else {
                        Server.logLookupHELO(time, hostname, attributes.toString());
                    }
                } catch (NameNotFoundException ex) {
                    this.attributes = null;
                    this.queryCount = 0;
                    CHANGED = true;
                    Server.logLookupHELO(time, hostname, "NXDOMAIN");
                }
            }

            public boolean isExpired7() {
                return System.currentTimeMillis() - lastQuery > 604800000;
            }
        }

        /**
         * Primeiro teste de estrutura de dados simples.
         *
         * @param helo
         * @return
         * @throws Exception
         */
        private static Attributes getAttributes(String hostname) throws NamingException {
            HELO heloObj = MAP.get(hostname);
            if (heloObj == null) {
                heloObj = new HELO(hostname);
                put(hostname, heloObj);
                return heloObj.attributes;
            } else {
                heloObj.queryCount++;
                heloObj.lastQuery = System.currentTimeMillis();
                CHANGED = true;
                return heloObj.attributes;
            }
        }

        private static Attribute getAttribute(
                String helo, String attribute) throws NamingException {
            Attributes attributes = getAttributes(helo);
            if (attributes == null) {
                return null;
            } else {
                return attributes.get(attribute);
            }
        }

        public static boolean match(String ip, String helo) {
            if ((helo = Domain.extractHost(helo, false)) == null) {
                // o HELO é nulo.
                return false;
            } else if (!Domain.containsDomain(helo)) {
                // o HELO não é um hostname válido.
                return false;
            } else if (SubnetIPv4.isValidIPv4(ip)) {
                long time = System.currentTimeMillis();
                try {
                    Attribute attribute = getAttribute(helo, "A");
                    if (attribute == null) {
                        Server.logMatchHELO(time, helo + " " + ip, "NXDOMAIN");
                        return false;
                    } else {
                        int address = SubnetIPv4.getAddressIP(ip);
                        NamingEnumeration enumeration = attribute.getAll();
                        while (enumeration.hasMoreElements()) {
                            String hostAddress = (String) enumeration.next();
                            int indexSpace = hostAddress.indexOf(' ') + 1;
                            hostAddress = hostAddress.substring(indexSpace);
                            if (SubnetIPv4.isValidIPv4(hostAddress)) {
                                if (address == SubnetIPv4.getAddressIP(hostAddress)) {
                                    Server.logMatchHELO(time, helo + " " + ip, "MATCH");
                                    return true;
                                }
                            }
                        }
                        Server.logMatchHELO(time, helo + " " + ip, "NOT MATCH");
                        return false;
                    }
                } catch (CommunicationException ex) {
                    Server.logMatchHELO(time, helo + " " + ip, "TIMEOUT");
                    return false;
                } catch (NamingException ex) {
                    Server.logMatchHELO(time, helo + " " + ip, "ERROR " + ex.getMessage());
                    return false;
                }
            } else if (SubnetIPv6.isValidIPv6(ip)) {
                long time = System.currentTimeMillis();
                try {
                    Attribute attribute = getAttribute(helo, "AAAA");
                    if (attribute == null) {
                        Server.logMatchHELO(time, helo + " " + ip, "NXDOMAIN");
                        return false;
                    } else {
                        short[] address = SubnetIPv6.split(ip);
                        NamingEnumeration enumeration = attribute.getAll();
                        while (enumeration.hasMoreElements()) {
                            String hostAddress = (String) enumeration.next();
                            int indexSpace = hostAddress.indexOf(' ') + 1;
                            hostAddress = hostAddress.substring(indexSpace);
                            if (SubnetIPv6.isValidIPv6(hostAddress)) {
                                if (Arrays.equals(address, SubnetIPv6.split(hostAddress))) {
                                    Server.logMatchHELO(time, helo + " " + ip, "MATCH");
                                    return true;
                                }
                            }
                        }
                        Server.logMatchHELO(time, helo + " " + ip, "NOT MATCH");
                        return false;
                    }
                } catch (CommunicationException ex) {
                    Server.logMatchHELO(time, helo + " " + ip, "TIMEOUT");
                    return false;
                } catch (NamingException ex) {
                    Server.logMatchHELO(time, helo + " " + ip, "ERROR " + ex.getMessage());
                    return false;
                }
            } else {
                // O parâmetro ip não é um IP válido.
                return false;
            }
        }

        public static synchronized void drop(String helo) {
            if (MAP.remove(helo) != null) {
                CHANGED = true;
            }
        }

        public static synchronized void put(String helo, HELO heloObj) {
            if (MAP.put(helo, heloObj) == null) {
                CHANGED = true;
            }
        }

        public static void dropExpired() {
            TreeSet<String> distributionKeySet = new TreeSet<String>();
            distributionKeySet.addAll(MAP.keySet());
            for (String helo : distributionKeySet) {
                HELO heloObj = MAP.get(helo);
                if (heloObj != null && heloObj.isExpired7()) {
                    drop(helo);
                }
            }
        }

        /**
         * Atualiza o registro mais consultado.
         */
        private static void refresh() {
            String heloMax = null;
            HELO heloObjMax = null;
            for (String helo : MAP.keySet()) {
                HELO heloObj = MAP.get(helo);
                if (heloObjMax == null) {
                    heloObjMax = heloObj;
                } else if (heloObjMax.queryCount < heloObj.queryCount) {
                    heloObjMax = heloObj;
                }
            }
            if (heloMax != null && heloObjMax != null
                    && heloObjMax.queryCount > 3) {
                try {
                    heloObjMax.refresh(heloMax);
                } catch (NamingException ex) {
                    Server.logError(ex);
                }
            }
            store();
        }

        private static synchronized void store() {
            if (CHANGED) {
                try {
                    long time = System.currentTimeMillis();
                    File file = new File("helo.map");
                    FileOutputStream outputStream = new FileOutputStream(file);
                    try {
                        SerializationUtils.serialize(MAP, outputStream);
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

        private static synchronized void load() {
            long time = System.currentTimeMillis();
            File file = new File("helo.map");
            if (file.exists()) {
                try {
                    HashMap<String, HELO> map;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        map = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    MAP.putAll(map);
                    Server.logLoad(time, file);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }
    }

    protected static String processPostfixSPF(
            String client, String ip, String sender, String helo,
            String recipient) throws ProcessException {
        if (sender != null && sender.length() > 0 && !Domain.isEmail(sender)) {
            return "action=REJECT [RBL] "
                    + sender + " is not a valid e-mail address.\n\n";
        } else if (!SubnetIPv4.isValidIPv4(ip) && !SubnetIPv6.isValidIPv6(ip)) {
            return "action=REJECT [RBL] "
                    + ip + " is not a valid IP.\n\n";
        } else {
            try {
                String result;
                SPF spf = CacheSPF.get(sender);
                if (spf == null) {
                    result = "NONE";
                } else if (spf.isInexistent()) {
                    // O domínio foi dado como inexistente inúmeras vezes.
                    // Rejeitar a mensagem pois há abuso de tentativas.
                    String dominio = Domain.extractDomain(sender, false);
                    return "action=REJECT [RBL] "
                            + dominio + " is non-existent internet domain.\n\n";
                } else {
                    result = spf.getResult(ip, sender, helo);
                }
                TreeSet<String> tokenSet = new TreeSet<String>();
                String ownerid = null;
                if (result.equals("FAIL")) {
                    return "action=REJECT "
                            + "[SPF] " + sender + " is not allowed to "
                            + "send mail from " + ip + ". "
                            + "Please see http://www.openspf.org/why.html?"
                            + "sender=" + sender + "&"
                            + "ip=" + ip + " for details.\n\n";
                } else if (result.equals("PASS")) {
                    // Quando fo PASS, significa que o domínio
                    // autorizou envio pelo IP, portanto o dono dele
                    // é responsavel pelas mensagens.
                    String host = Domain.extractHost(sender, true);
                    if (CacheProvider.contains(host)) {
                        // Listar apenas o remetente se o
                        // hostname for um provedor de e-mail.
                        tokenSet.add(sender);
                    } else {
                        // Não é um provedor então
                        // o domínio e subdomínios devem ser listados.
                        String dominio = "." + Domain.extractDomain(sender, false);
                        String subdominio = host;
                        while (!subdominio.equals(dominio)) {
                            tokenSet.add(subdominio);
                            int index = subdominio.indexOf('.', 1);
                            subdominio = subdominio.substring(index);
                        }
                        tokenSet.add(dominio);
                        tokenSet.add(Domain.extractDomain(sender, true));
                        if ((ownerid = Domain.getOwnerID(sender)) != null) {
                            tokenSet.add(ownerid);
                        }
                    }
                } else if (CacheHELO.match(ip, helo)) {
                    // Se o HELO apontar para o IP,
                    // então o dono do HELO é o responsável.
                    if (!helo.startsWith(".")) {
                        helo = "." + helo;
                    }
                    String dominio = Domain.extractDomain(helo, true);
                    String subdominio = helo;
                    while (!subdominio.equals(dominio)) {
                        tokenSet.add(subdominio);
                        int index = subdominio.indexOf('.', 1);
                        subdominio = subdominio.substring(index);
                    }
                    tokenSet.add(dominio);
                    if ((ownerid = Domain.getOwnerID(helo)) != null) {
                        tokenSet.add(ownerid);
                    }
                } else {
                    // Em qualquer outro caso,
                    // o responsável é o dono do IP.
                    if (SubnetIPv4.isValidIPv4(ip)) {
                        // Formalizar notação IPv4.
                        tokenSet.add(SubnetIPv4.normalizeIPv4(ip));
                    } else if (SubnetIPv6.isValidIPv6(ip)) {
                        // Formalizar notação IPv6.
                        tokenSet.add(SubnetIPv6.normalizeIPv6(ip));
                    }
                    if ((ownerid = Subnet.getOwnerID(ip)) != null) {
                        tokenSet.add(ownerid);
                    }
                    String inetnum = Subnet.getInetnum(ip);
                    if (inetnum != null) {
                        tokenSet.add(inetnum);
                    }
                }
                if (CacheWhite.contains(client, sender)) {
                    // Calcula frequencia de consultas.
                    SPF.addQuery(tokenSet);
                    // Adcionar ticket ao cabeçalho da mensagem.
                    long time = System.currentTimeMillis();
                    String ticket = SPF.createTicket(tokenSet);
                    Server.logTicket(time, ip + " " + sender + " " + helo, tokenSet);
                    return "action=PREPEND "
                            + "Received-SPFBL: " + result + " " + ticket + "\n\n";
                } else if (CacheTrap.contains(client, recipient)) {
                    // Calcula frequencia de consultas.
                    SPF.addQuery(tokenSet);
                    // Spamtrap. Denúnica automática.
                    long time = System.currentTimeMillis();
                    String ticket = SPF.createTicket(tokenSet);
                    Server.logTicket(time, ip + " " + sender + " " + helo, tokenSet);
                    TreeSet<String> complainSet = CacheComplain.add(ticket);
                    Server.logQuery(time, "SPFSP", client, "SPAM " + ticket, "OK " + complainSet);
                    return "action=DISCARD [RBL] discarded by spamtrap.\n\n";
                } else if (CacheBlock.contains(client, ip, sender, helo, ownerid, result)) {
                    // Calcula frequencia de consultas.
                    SPF.addQuery(tokenSet);
                    // Bloqueio. Denúnica automática.
                    long time2 = System.currentTimeMillis();
                    String ticket = SPF.createTicket(tokenSet);
                    Server.logTicket(time2, ip + " " + sender + " " + helo, tokenSet);
                    TreeSet<String> complainSet = CacheComplain.add(ticket);
                    Server.logQuery(time2, "SPFSP", client, "SPAM " + ticket, "OK " + complainSet);
                    return "action=REJECT [RBL] "
                            + "you are permanently blocked in this server.\n\n";
                } else if (SPF.isBlocked(tokenSet)) {
                    // Calcula frequencia de consultas.
                    SPF.addQuery(tokenSet);
                    return "action=REJECT [RBL] "
                            + "you are permanently blocked in this server.\n\n";
                } else if (SPF.isBlacklisted(tokenSet)) {
                    // Pelo menos um token está listado.
                    return "action=DEFER [RBL] "
                            + "you are temporarily blocked on this server.\n\n";
                } else if (SPF.isGreylisted(tokenSet)) {
                    // Pelo menos um token está em greylisting.
                    return "action=DEFER [RBL] "
                            + "you are greylisted on this server.\n\n";
                } else {
                    // Calcula frequencia de consultas.
                    SPF.addQuery(tokenSet);
                    // Adcionar ticket ao cabeçalho da mensagem.
                    long time = System.currentTimeMillis();
                    String ticket = SPF.createTicket(tokenSet);
                    Server.logTicket(time, ip + " " + sender + " " + helo, tokenSet);
                    return "action=PREPEND "
                            + "Received-SPFBL: " + result + " " + ticket + "\n\n";
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
                    TreeSet<String> tokenSet = CacheComplain.add(ticket);
                    if (tokenSet == null) {
                        result = "DUPLICATE COMPLAIN\n";
                    } else {
                        result = "OK " + tokenSet + "\n";
                    }
                } else if (firstToken.equals("HAM") && tokenizer.countTokens() == 1) {
                    String ticket = tokenizer.nextToken();
                    TreeSet<String> tokenSet = CacheComplain.remove(ticket);
                    if (tokenSet == null) {
                        result = "ALREADY REMOVED\n";
                    } else {
                        result = "OK " + tokenSet + "\n";
                    }
                } else if (firstToken.equals("REFRESH") && tokenizer.countTokens() == 1) {
                    String address = tokenizer.nextToken();
                    if (CacheSPF.refresh(address, true)) {
                        result = "UPDATED\n";
                    } else {
                        result = "NOT LOADED\n";
                    }
                } else if ((firstToken.equals("SPF") || tokenizer.countTokens() == 4)
                        || tokenizer.countTokens() == 2 || tokenizer.countTokens() == 1
                        || (firstToken.equals("CHECK") && tokenizer.countTokens() == 3)
                        || (firstToken.equals("CHECK") && tokenizer.countTokens() == 2)) {
                    try {
                        String ip;
                        String sender;
                        String helo;
                        String recipient;
                        if (firstToken.equals("SPF")) {
                            // Nova formatação de consulta.
                            ip = tokenizer.nextToken();
                            sender = tokenizer.nextToken();
                            helo = tokenizer.nextToken();
                            recipient = tokenizer.nextToken();
                            ip = ip.substring(1,ip.length()-1);
                            sender = sender.substring(1,sender.length()-1);
                            helo = helo.substring(1,helo.length()-1);
                            recipient = recipient.substring(1,recipient.length()-1);
                            if (sender.length() == 0) {
                                sender = null;
                            }
                            if (recipient.length() == 0) {
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
                        }
                        if (!Subnet.isValidIP(ip)) {
                            return "ERROR: INVALID IP\n";
                        } else if (sender != null && !Domain.isEmail(sender)) {
                            return "ERROR: INVALID SENDER\n";
                        } else {
                            SPF spf = CacheSPF.get(sender);
                            if (spf == null) {
                                result = "NONE";
                            } else if (spf.isInexistent()) {
                                return "ERROR: NXDOMAIN\n";
                            } else {
                                result = spf.getResult(ip, sender, helo);
                            }
                            TreeSet<String> tokenSet = new TreeSet<String>();
                            String ownerid = null;
                            if (result.equals("FAIL")) {
                                return "FAIL\n";
                            } else if (result.equals("PASS")) {
                                // Quando fo PASS, significa que o domínio
                                // autorizou envio pelo IP, portanto o dono dele
                                // é responsavel pelas mensagens.
                                String host = Domain.extractHost(sender, true);
                                if (CacheProvider.contains(host)) {
                                    // Listar apenas o remetente se o
                                    // hostname for um provedor de e-mail.
                                    tokenSet.add(sender);
                                } else {
                                    // Não é um provedor então
                                    // o domínio e subdominios devem ser listados.
                                    String dominio = "." + Domain.extractDomain(sender, false);
                                    String subdominio = host;
                                    while (!subdominio.equals(dominio)) {
                                        tokenSet.add(subdominio);
                                        int index = subdominio.indexOf('.', 1);
                                        subdominio = subdominio.substring(index);
                                    }
                                    tokenSet.add(dominio);
                                    tokenSet.add(Domain.extractDomain(sender, true));
                                    if ((ownerid = Domain.getOwnerID(sender)) != null) {
                                        tokenSet.add(ownerid);
                                    }
                                }
                            } else if (CacheHELO.match(ip, helo)) {
                                // Se o HELO apontar para o IP,
                                // então o dono do HELO é o responsável.
                                if (!helo.startsWith(".")) {
                                    helo = "." + helo;
                                }
                                String dominio = Domain.extractDomain(helo, true);
                                String subdominio = helo;
                                while (!subdominio.equals(dominio)) {
                                    tokenSet.add(subdominio);
                                    int index = subdominio.indexOf('.', 1);
                                    subdominio = subdominio.substring(index);
                                }
                                tokenSet.add(dominio);
                                if ((ownerid = Domain.getOwnerID(helo)) != null) {
                                    tokenSet.add(ownerid);
                                }
                            } else {
                                // Em qualquer outro caso,
                                // o responsável é o dono do IP.
                                if (SubnetIPv4.isValidIPv4(ip)) {
                                    // Formalizar notação IPv4.
                                    tokenSet.add(SubnetIPv4.normalizeIPv4(ip));
                                } else if (SubnetIPv6.isValidIPv6(ip)) {
                                    // Formalizar notação IPv6.
                                    tokenSet.add(SubnetIPv6.normalizeIPv6(ip));
                                }
                                if ((ownerid = Subnet.getOwnerID(ip)) != null) {
                                    tokenSet.add(ownerid);
                                }
                                String inetnum = Subnet.getInetnum(ip);
                                if (inetnum != null) {
                                    tokenSet.add(inetnum);
                                }
                            }
                            if (firstToken.equals("CHECK")) {
                                result += "\n";
                                TreeMap<String, Distribution> distributionMap = CacheDistribution.getMap(tokenSet);
                                for (String token : tokenSet) {
                                    float probability;
                                    Status status;
                                    String frequency;
                                    if (distributionMap.containsKey(token)) {
                                        Distribution distribution = distributionMap.get(token);
                                        probability = distribution.getMinSpamProbability();
                                        status = distribution.getStatus(token);
                                        frequency = distribution.getFrequencyLiteral();
                                    } else {
                                        probability = 0.0f;
                                        status = SPF.Status.WHITE;
                                        frequency = "undefined";
                                    }
                                    result += token + " " + frequency + " " + status.name() + " "
                                            + Server.DECIMAL_FORMAT.format(probability) + "\n";
                                }
                                return result;
                            } else if (CacheWhite.contains(client, sender)) {
                                // Calcula frequencia de consultas.
                                SPF.addQuery(tokenSet);
                                // Anexando ticket ao resultado.
                                long time = System.currentTimeMillis();
                                String ticket = SPF.createTicket(tokenSet);
                                Server.logTicket(time, ip + " " + sender + " " + helo, tokenSet);
                                return result + " " + ticket + "\n";
                            } else if (CacheTrap.contains(client, recipient)) {
                                // Calcula frequencia de consultas.
                                SPF.addQuery(tokenSet);
                                // Spamtrap. Denunciar automaticamente.
                                long time = System.currentTimeMillis();
                                String ticket = SPF.createTicket(tokenSet);
                                Server.logTicket(time, ip + " " + sender + " " + helo, tokenSet);
                                TreeSet<String> complainSet = CacheComplain.add(ticket);
                                Server.logQuery(time, "SPFSP", client, "SPAM " + ticket, "OK " + complainSet);
                                return "SPAMTRAP\n";
                            } else if (CacheBlock.contains(client, ip, sender, helo, ownerid, result)) {
                                // Calcula frequencia de consultas.
                                SPF.addQuery(tokenSet);
                                // Bloqueio. Denunciar automaticamente.
                                long time = System.currentTimeMillis();
                                String ticket = SPF.createTicket(tokenSet);
                                Server.logTicket(time, ip + " " + sender + " " + helo, tokenSet);
                                TreeSet<String> complainSet = CacheComplain.add(ticket);
                                Server.logQuery(time, "SPFSP", client, "SPAM " + ticket, "OK " + complainSet);
                                return "BLOCKED\n";
                            } else if (SPF.isBlocked(tokenSet)) {
                                // Calcula frequencia de consultas.
                                SPF.addQuery(tokenSet);
                                // Pelo menos um token do
                                // conjunto está bloqueado.
                                return "BLOCKED\n";
                            } else if (SPF.isBlacklisted(tokenSet)) {
                                // Pelo menos um token do
                                // conjunto está em lista negra.
                                return "LISTED\n";
                            } else if (SPF.isGreylisted(tokenSet)) {
                                // Pelo menos um token do
                                // conjunto está em greylisting.
                                return "GREYLIST\n";
                            } else {
                                // Calcula frequencia de consultas.
                                SPF.addQuery(tokenSet);
                                // Anexando ticket ao resultado.
                                long time = System.currentTimeMillis();
                                String ticket = SPF.createTicket(tokenSet);
                                Server.logTicket(time, ip + " " + sender + " " + helo, tokenSet);
                                return result + " " + ticket + "\n";
                            }
                        }
                    } catch (ProcessException ex) {
                        if (ex.getMessage().equals("ERROR: HOST NOT FOUND")) {
                            // Considerar FAIL sempre que o hostname não existir.
                            return "FAIL";
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

    /**
     * Classe que representa uma reclamação. Possui mecanismo de vencimento da
     * reclamação.
     */
    private static final class Complain implements Serializable {

        private static final long serialVersionUID = 1L;
        private final Date date;
        private final TreeSet<String> tokenSet = new TreeSet<String>();

        public Complain(String ticket) throws ProcessException {
            String complain = Server.decrypt(ticket);
            int index = complain.indexOf(' ');
            date = getTicketDate(complain.substring(0, index));
            if (isExpired5()) {
                // Ticket vencido com mais de 5 dias.
                throw new ProcessException("ERROR: TICKET EXPIRED");
            } else {
                complain = complain.substring(index + 1);
                StringTokenizer tokenizer = new StringTokenizer(complain, " ");
                while (tokenizer.hasMoreTokens()) {
                    String token = tokenizer.nextToken();
                    CacheDistribution.get(token, true).addSpam();
                    tokenSet.add(token);
                }
            }
        }

        public boolean isExpired3() {
            return System.currentTimeMillis() - date.getTime() > 259200000;
        }

        public boolean isExpired5() {
            return System.currentTimeMillis() - date.getTime() > 432000000;
        }

        public boolean isExpired7() {
            return System.currentTimeMillis() - date.getTime() > 604800000;
        }

        public TreeSet<String> getTokenSet() {
            TreeSet<String> tokenSetClone = new TreeSet<String>();
            tokenSetClone.addAll(this.tokenSet);
            return tokenSetClone;
        }

        public void removeComplains() {
            Server.logHamSPF(tokenSet);
            // Retira todas as reclamações.
            while (!tokenSet.isEmpty()) {
                String token = tokenSet.pollFirst();
                Distribution distribution = CacheDistribution.get(token, false);
                if (distribution != null) {
                    distribution.removeSpam();
                }
            }
        }

        @Override
        public String toString() {
            return Server.formatTicketDate(date);
        }
    }

    public static void addQuery(TreeSet<String> tokenSet) {
        for (String token : tokenSet) {
            Distribution distribution = CacheDistribution.get(token, false);
            if (distribution != null) {
                distribution.addQuery();
            }
        }
    }

    public static long getComplainTTL(String token) {
        Distribution distribution = CacheDistribution.get(token, false);
        if (distribution == null) {
            // Distribuição não encontrada.
            // Considerar que não está listado.
            return 0;
        } else {
            // Transformar em minutos.
            return distribution.getComplainTTL() / 60000;
        }
    }

    public static boolean isBlacklisted(String token) {
        Distribution distribution = CacheDistribution.get(token, false);
        if (distribution == null) {
            // Distribuição não encontrada.
            // Considerar que não está listado.
            return false;
        } else {
            return distribution.isBlacklisted(token);
        }
    }

    public static boolean isBlocked(String token) {
        Distribution distribution = CacheDistribution.get(token, false);
        if (distribution == null) {
            // Distribuição não encontrada.
            // Considerar que não está listado.
            return false;
        } else {
            return distribution.isBlocked(token);
        }
    }

    private static boolean isGreylisted(TreeSet<String> tokenSet) {
        // TODO: implementar mecanismo de greylisting.
        return false;
    }

    private static boolean isBlacklisted(TreeSet<String> tokenSet) {
        boolean blacklisted = false;
        for (String token : tokenSet) {
            if (isBlacklisted(token)) {
                blacklisted = true;
            }
        }
        return blacklisted;
    }

    private static boolean isBlocked(TreeSet<String> tokenSet) {
        boolean blocked = false;
        for (String token : tokenSet) {
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
     * Constante que determina o limiar de listagem.
     */
    private static final float LIMIAR = 0.25f;

    /**
     * Classe que representa a distribuição binomial entre SPAM e HAM. O valor
     * máximo é 255.
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
            if (status == Status.WHITE) {
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
                return "undefined";
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

        public synchronized void addQuery() {
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

        public synchronized float getMinSpamProbability() {
            return getSpamProbability()[0];
        }

        public synchronized float getMaxSpamProbability() {
            return getSpamProbability()[2];
        }

        private synchronized float[] getSpamProbability() {
            float[] probability = new float[3];
            if (frequency == null) {
                // Se não houver frequência definida,
                // considerar probabilidade zero
                // pela impossibilidade de cálculo.
                return probability;
            } else if (complain < 3) {
                // Se a quantida total de reclamações for
                // menor que três, considerar probabilidade zero
                // por conta na baixa precisão do cálculo.
                return probability;
            } else if (frequency.getAverage() == 0.0d) {
                // Impossível calcular por conta da divisão por zero.
                // Considerar probabilidade zero.
                return probability;
            } else {
                // Estimativa máxima do total de mensagens por
                // semana calculado pela amostragem mais recente.
                double semana = 60 * 60 * 24 * 7;
                float probabilityMin = (float) complain / (float) (semana / frequency.getMinimum());
                if (probabilityMin < 0) {
                    probabilityMin = 0.0f;
                } else if (probabilityMin > 1.0) {
                    probabilityMin = 1.0f;
                }
                float probabilityAvg = (float) complain / (float) (semana / frequency.getAverage());
                if (probabilityAvg < 0) {
                    probabilityAvg = 0.0f;
                } else if (probabilityAvg > 1.0) {
                    probabilityAvg = 1.0f;
                }
                float probabilityMax = (float) complain / (float) (semana / frequency.getMaximum());
                if (probabilityMax < 0) {
                    probabilityMax = 0.0f;
                } else if (probabilityMax > 1.0) {
                    probabilityMax = 1.0f;
                }
                probability[0] = probabilityMin;
                probability[1] = probabilityAvg;
                probability[2] = probabilityMax;
                return probability;
            }
        }

        /**
         * Máquina de estados para listar em um pico e retirar a listagem
         * somente quando o total cair consideravelmente após este pico.
         *
         * @return o status atual da distribuição.
         */
        public synchronized Status getStatus(String token) {
            if (status == Status.BLOCK) {
                float max = getMaxSpamProbability();
                if (max < LIMIAR/2) {
                    status = Status.GRAY;
                    CacheBlock.dropExact(token);
                }
            } else {
                float[] probability = getSpamProbability();
                float min = probability[0];
                float max = probability[2];
                if (min > 0.5f && max > 0.75 && complain > 7) {
                    // Condição especial que bloqueia
                    // definitivamente o responsável.
                    status = Status.BLOCK;
                    CacheBlock.addAndDisseminate(token);
                } else if (max == 0.0f) {
                    status = Status.WHITE;
                } else if (min > LIMIAR) {
                    status = Status.BLACK;
                } else if (status == Status.GRAY && min > LIMIAR/2) {
                    status = Status.BLACK;
                } else if (status == Status.BLACK && max < LIMIAR/2) {
                    status = Status.GRAY;
                }
            }
            return status;
        }

        /**
         * Verifica se o estado atual da distribuição é blacklisted.
         *
         * @param query se contabiliza uma consulta com a verificação.
         * @return verdadeiro se o estado atual da distribuição é blacklisted.
         */
        public boolean isBlacklisted(String token) {
            return getStatus(token) == Status.BLACK;
        }

        public boolean isBlocked(String token) {
            return getStatus(token) == Status.BLOCK;
        }

        public synchronized void removeSpam() {
            if (complain > 0) {
                complain--;
                CacheDistribution.CHANGED = true;
            }
        }

        public synchronized void addSpam() {
            if (complain < Integer.MAX_VALUE) {
                complain++;
                lastComplain = System.currentTimeMillis();
                CacheDistribution.CHANGED = true;
            }
        }

        @Override
        public String toString() {
            return Float.toString(getMinSpamProbability());
        }
    }
}
