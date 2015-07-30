/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.com.allchemistry.spf;

import br.com.allchemistry.core.NormalDistribution;
import br.com.allchemistry.whois.Domain;
import br.com.allchemistry.core.ProcessException;
import br.com.allchemistry.core.Server;
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
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.StringTokenizer;
import java.util.Timer;
import java.util.TimerTask;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.InvalidAttributeIdentifierException;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.commons.validator.routines.DomainValidator;

/**
 * Representa o registro SPF de um deterninado host.
 * Implementação da RFC 4406, exceto os Macros da seção 8 por enquanto.
 * 
 * Quando a consulta é feita, o resultado do SPF é 
 * considerado para determinar o responsável pela mensagem.
 * Uma vez encontrado o responsável, um ticket SPFBL 
 * é gerado através de criptografia na base 64.
 * Este ticket é enviado juntamente o qualificador SPF da consulta.
 * O cliente da consulta deve extrair o ticket do resultado 
 * e adicionar no cabeçalho da mensagem utilizando o campo "Received-SPFBL".
 * 
 * A regra de determinação de responsabilidade é usada para 
 * gerar o ticket SPFBL e funciona da seguinte forma:
 *    1. Se retornar PASS, o remetente é o responsável pela mensagem ou
 *    2. Caso contrário, o host é responsável pela mensagem.
 * 
 * No primeiro caso, onde o remetente é responsável pela mensagem,
 * o ticket é gerado com a seguinte regra:
 *    1. Se o domínio do rementente estiver na lista de provedores,
 *       então o endereço de e-mail completo é utilizado ou
 *    2. Caso contrário, o host e domínio do rementente são utilizados.
 * 
 * No segundo caso, onde o host é responsável pela mensagem,
 * o ticket é gerado com a seguinte regra:
 *    1. Se o HELO apontar para o IP, então o próprio 
 *       HELO e o domínio do HELO são utilizados ou
 *    2. Caso contrário, o IP é utilizado.
 * 
 * Todas as consultas são registradas numa distribuição de probabilidade,
 * onde é possível alternar de HAM para SPAM utilizando o ticket gerado.
 * Uma vez recebida a reclamação com o ticket, o serviço 
 * descriptografa o ticket e extrai os responsaveis pelo envio.
 * 
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
    
    private long lastRefresh = 0; // Última vez que houve atualização do registro em milisegundos.
    private static final int REFRESH_TIME = 7; // Prazo máximo que o registro deve permanecer em cache em dias.
    
    private SPF(String hostname) throws ProcessException {
        this.hostname = hostname;
        refresh(false);
    }
    
    /**
     * http://www.openspf.org/FAQ/Best_guess_record
     */
    private static final String BEST_GUESS = "v=spf1 a/24 mx/24 ptr ?all";
    
    /**
     * Mapa de registros manuais de SPF caso o domínio não tenha um.
     */
    private static HashMap<String,String> GUESS_MAP = new HashMap<String,String>();
    
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean GUESS_CHANGED = false;
    
    public synchronized static void addGuess(String hostname,
            String spf) throws ProcessException {
        hostname = Domain.extractHost(hostname, false);
        if (!Domain.containsDomain(hostname)) {
            throw new ProcessException("ERROR: HOSTNAME INVALID");
        } else if (!spf.equals(GUESS_MAP.put("." + hostname, spf))) {
            GUESS_CHANGED = true;
        }
    }
    
    /**
     * Consulta o registro SPF nos registros DNS do domínio.
     * Se houver mais de dois registros diferentes,
     * realiza o merge do forma a retornar um único registro.
     * @param hostname o nome do host para consulta do SPF.
     * @return o registro SPF consertado, padronuzado e mergeado.
     * @throws ProcessException 
     */
    private static LinkedList<String> getRegistrySPF(String hostname) throws ProcessException {
        try {
            LinkedList<String> registryList = new LinkedList<String>();
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
            if (registryList.isEmpty()) {
                hostname = "." + hostname;
                if (GUESS_MAP.containsKey(hostname)) {
                    // Significa que um palpite SPF 
                    // foi registrado ara este host.
                    // Neste caso utilizar o paltpite.
                    registryList.add(GUESS_MAP.get(hostname));
                } else {
                    // Se não hoouver palpite específico para o host,
                    // utilizar o palpite padrão.
                    // http://www.openspf.org/FAQ/Best_guess_record
                    registryList.add(BEST_GUESS);
                }
            }
            return registryList;
        } catch (NamingException ex) {
            throw new ProcessException("ERROR: HOST NOT FOUND", ex);
        } catch (Exception ex) {
            throw new ProcessException("ERROR: FATAL", ex);
        }
    }
    
    /**
     * Algoritmo para consertar e padronizar o registro SPF.
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
     * @param midleList lista dos mecanismos centrais.
     * @param errorList lista dos mecanismos com erro de sintaxe.
     */
    private static void mergeMechanism(
            LinkedList<String> midleList,
            LinkedList<String> errorList
    ) {
        while (!errorList.isEmpty()) {
            boolean fixed = false;
            if (errorList.size() > 1) {
                for (int index = 1; index < errorList.size(); index++) {
                    String tokenFix = errorList.getFirst();
                    for (String tokenError : errorList.subList(1, index+1)) {
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
    
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean SPF_CHANGED = false;
    
    /**
     * Atualiza o registro SPF de um host.
     * @throws ProcessException se houver falha no processamento.
     */
    private void refresh(boolean load) throws ProcessException {
        try {
            LinkedList<String> registryList = getRegistrySPF(hostname);
            if (registryList.isEmpty()) {
                Server.logQuerySPF(hostname, "no registry");
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
                for (String registry : registryList) {
                    boolean errorRegistry = false;
                    StringTokenizer tokenizer = new StringTokenizer(registry, " ");
                    while (tokenizer.hasMoreTokens()) {
                        String token = tokenizer.nextToken();
                        if (visitedTokens.contains(token)) {
                            // Token já visitado.
                        } else if (token.equals("v=spf1")) {
                            // Nada deve ser feito.
                        } else if (token.equals("v=msv1")) {
                            // Nada deve ser feito.
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
                    if (errorRegistry) {
                        // Log do registro com erro.
                        Server.logErrorSPF(hostname, registry);
                    } else {
                        // Log do registro sem erro.
                        Server.logQuerySPF(hostname, registry);
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
                SPF_CHANGED = true;
                this.queries = 0;
                this.lastRefresh = System.currentTimeMillis();
            }
        } catch (ProcessException ex) {
            if (ex.getMessage().equals("ERROR: HOST NOT FOUND")) {
                // Host não existe mais.
                // Apagar registro do cache.
                removeSPF(hostname);
            }
            throw ex;
        }
    }
    
    public static void main(String[] args) {
        try {
            System.out.println(SPF.isMechanismInclude("include:ip4._spf.%{d}"));
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
            System.exit(0);
        }
    }
    
    /**
     * Verifica se o token é um mecanismo all válido.
     * @param token o token a ser verificado.
     * @return verdadeiro se o token é um mecanismo all válido.
     */
    private static boolean isMechanismAll(String token) {
        return Pattern.matches(
                "^(\\+|-|~|\\?)?all$", token.toLowerCase()
                );
    }
    
    /**
     * Verifica se o token é um mecanismo ip4 válido.
     * @param token o token a ser verificado.
     * @return verdadeiro se o token é um mecanismo ip4 válido.
     */
    private static boolean isMechanismIPv4(String token) {
        return Pattern.matches(
                "^(\\+|-|~|\\?)?ip4:"
                + "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}"
                + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
                + "(/[0-9]{1,2})?"
                + "$", token.toLowerCase()
                );
    }
    
    /**
     * Extrai um CIDR de IPv4 válido.
     * @param token o token a ser verificado.
     * @return um CIDR de IPv4 válido.
     */
    private static String extractIPv4CIDR(String token) {
         Pattern pattern = Pattern.compile(
                "(:|^)((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}"
                + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
                + "(/[0-9]{1,2})?)$"
                );
        Matcher matcher = pattern.matcher(token.toLowerCase());
        if (matcher.find()) {
            return matcher.group(2);
        } else {
            return null;
        }
    }
    
    /**
     * Verifica se o token é um mecanismo ip6 válido.
     * @param token o token a ser verificado.
     * @return verdadeiro se o token é um mecanismo ip6 válido.
     */
    private static boolean isMechanismIPv6(String token) {
        return Pattern.matches(
                "^(\\+|-|~|\\?)?ip6:"
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
                + "$", token
                );
    }
    
    /**
     * Extrai um CIDR de IPv6 válido.
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
                 + "(%.+)?(\\/[0-9]{1,3})?)$"
                );
        Matcher matcher = pattern.matcher(token);
        if (matcher.find()) {
            return matcher.group(2);
        } else {
            return null;
        }
    }
    
    /**
     * Verifica se o token é um mecanismo a válido.
     * @param token o token a ser verificado.
     * @return verdadeiro se o token é um mecanismo a válido.
     */
    private static boolean isMechanismA(String token) {
        return Pattern.matches(
                "^"
                + "(\\+|-|~|\\?)?a"
                + "(:_?(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\\.?)?"
                + "(/[0-9]{1,2})?"
                + "$", token.toLowerCase()
                );
    }
    
    /**
     * Verifica se o token é um mecanismo mx válido.
     * @param token o token a ser verificado.
     * @return verdadeiro se o token é um mecanismo mx válido.
     */
    private static boolean isMechanismMX(String token) {
        return Pattern.matches(
                "^(\\+|-|~|\\?)?mx"
                + "(:_?(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\\.?)?"
                + "(\\.|/[0-9]{1,2})?"
                + "$", token.toLowerCase()
                );
    }
    
    /**
     * Verifica se o token é um mecanismo ptr válido.
     * @param token o token a ser verificado.
     * @return verdadeiro se o token é um mecanismo ptr válido.
     */
    private static boolean isMechanismPTR(String token) {
        return Pattern.matches(
                "^(\\+|-|~|\\?)?ptr"
                + "(:_?(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\\.?)?"
                + "$", token.toLowerCase()
                );
    }
    
    /**
     * Verifica se o token é um mecanismo existis válido.
     * @param token o token a ser verificado.
     * @return verdadeiro se o token é um mecanismo existis válido.
     */
    private static boolean isMechanismExistis(String token) {
        return Pattern.matches(
                "^(\\+|-|~|\\?)?exists:"
                + "(_?(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\\.?)"
                + "$", token.toLowerCase()
                );
    }
    
    /**
     * Verifica se o token é um mecanismo include válido.
     * @param token o token a ser verificado.
     * @return verdadeiro se o token é um mecanismo include válido.
     */
    private static boolean isMechanismInclude(String token) {
        return Pattern.matches(
                "^(\\+|-|~|\\?)?include:"
                + "(_?(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\\.?)"
                + "$", token.toLowerCase()
                );
    }
    
    /**
     * Verifica se o token é um modificador redirect válido.
     * @param token o token a ser verificado.
     * @return verdadeiro se o token é um modificador redirect válido.
     */
    private static boolean isModifierRedirect(String token) {
        return Pattern.matches(
                "^redirect="
                + "(_?(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\\.?)"
                + "$", token.toLowerCase()
                );
    }
    
    /**
     * Verifica se o token é um modificador explanation válido.
     * @param token o token a ser verificado.
     * @return verdadeiro se o token é um modificador explanation válido.
     */
    private static boolean isModifierExplanation(String token) {
        return Pattern.matches(
                "^exp="
                + "(_?(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\\.?)"
                + "$", token.toLowerCase()
                );
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
     * Retorna o resultado SPF para um IP especifico.
     * @param ip o IP a ser verificado.
     * @return o resultado SPF para um IP especifico.
     * @throws ProcessException se houver falha no processamento.
     */
    public String getResult(String ip) throws ProcessException {
        Qualifier qualifier = getQualifier(ip, 0, new TreeSet<String>());
        if (qualifier == null) {
            return "NONE";
        } else {
            return qualifier.name();
        }
    }
    
    /**
     * Retorna o qualificador para uma consulta SPF.
     * @param ip o IP a ser verificado.
     * @param deep a profundiade de navegação da ávore SPF.
     * @param hostVisitedSet o conjunto de hosts visitados.
     * @return o qualificador da consulta SPF.
     * @throws ProcessException se houver falha no processamento.
     */
    private Qualifier getQualifier(String ip, int deep,
            TreeSet<String> hostVisitedSet) throws ProcessException {
        if (deep > 10) {
            return null; // Evita excesso de consultas.
        } else if (hostVisitedSet.contains(getHostname())) {
            return null; // Evita looping infinito.
        } else if (redirect == null) {
            hostVisitedSet.add(getHostname());
            for (Mechanism mechanism : mechanismList) {
                if (mechanism instanceof MechanismInclude) {
                    try {
                        MechanismInclude include = (MechanismInclude) mechanism;
//                        SPF spf = include.getSPF();
                        Qualifier qualifier = include.getQualifierSPF(
                                ip, deep + 1, hostVisitedSet);
                        if (qualifier == null) {
                            // Nenhum qualificador foi definido
                            // então continuar busca.
                        } else {
                            return qualifier;
                        }
                    } catch (ProcessException ex) {
                        if (ex.getMessage().equals("ERROR: HOST NOT FOUND")) {
                            // Não foi possível fazer o include.
                            // O host mencionado não existe.
                            // Continuar a verificação dos demais mecanismos.
                        } else {
                            throw ex;
                        }
                    }
                } else if (mechanism instanceof MechanismPTR) {
                    if (deep == 0 && mechanism.match(ip)) {
                        // Mecanismo PTR só será processado
                        // no primeiro nível da árvore.
                        return mechanism.getQualifier();
                    }
                } else if (mechanism.match(ip)) {
                    return mechanism.getQualifier();
                }
            }
            if (error) {
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
        } else {
            hostVisitedSet.add(getHostname());
            SPF spf = SPF.getSPF(redirect);
            return spf.getQualifier(ip, 0, hostVisitedSet);
        }
    }
    
    /**
     * Retorna o hostname do registro SPF.
     * @return o hostname do registro SPF.
     */
    public String getHostname() {
        return hostname;
    }
    
    /**
     * Retorna o dominio de explicação do registro SPF.
     * Não sei ainda do que se trata.
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
        
        public abstract boolean match(String ip) throws ProcessException;
        
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
            String inetnum = expression.substring(index+1);
            index = inetnum.indexOf('/');
            int addressLocal;
            int maskLocal;
            if (index == -1) {
                maskLocal = 0xFFFFFFFF;
                addressLocal = SubnetIPv4.getAddressIP(inetnum);
            } else {
                maskLocal = SubnetIPv4.getMaskNet(inetnum.substring(index+1));
                addressLocal = SubnetIPv4.getAddressIP(inetnum.substring(0,index)) & maskLocal;
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
        public boolean match(String ip) {
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
            int index = expression.indexOf(':');
            String inetnum = expression.substring(index+1);
            index = inetnum.indexOf('/');
            if (index == -1) {
                this.mask = SubnetIPv6.getMaskIPv6(128);
                this.address = SubnetIPv6.split(inetnum);
            } else {
                this.mask = SubnetIPv6.getMaskIPv6(inetnum.substring(index+1));
                this.address = SubnetIPv6.split(inetnum.substring(0,index), mask);
            }
        }
        
        @Override
        public boolean match(String ip) {
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
            if (load) {
                loadList();
            }
        }
        
        private synchronized void loadList() {
            if (!mechanismList.isEmpty()) {
                loaded = true; // Temporário
            } else if (!loaded) {
                // Carregamento de lista.
                String expression = getExpression();
                if (!Character.isLetter(expression.charAt(0))) {
                    // Expressão com qualificador.
                    // Extrair qualificador.
                    expression = expression.substring(1);
                }
                String hostName;
                int indexDomain = expression.indexOf(':');
                int indexPrefix = expression.indexOf('/');
                if (indexDomain > 0 && indexPrefix > indexDomain) {
                    hostName = expression.substring(indexDomain + 1, indexPrefix);
                } else if (indexDomain > 0) {
                    hostName = expression.substring(indexDomain + 1);
                } else {
                    hostName = getHostname();
                }
                try {
                    Attributes attributes = Server.INITIAL_DIR_CONTEXT.getAttributes(
                            "dns:/" + hostName, new String[]{"A"});
                    Attribute attribute = attributes.get("A");
                    if (attribute != null) {
                        NamingEnumeration enumeration = attribute.getAll();
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
                            if (indexPrefix > 0) {
                                hostAddress += expression.substring(indexPrefix);
                            }
                            mechanismList.add(new MechanismIPv4(hostAddress));
                        }
                    }
                } catch (NamingException ex) {
                    // Não encontrou registro MX para o host.
                }
                loaded = true;
            }
        }
        
        @Override
        public boolean match(String ip) throws ProcessException {
            loadList();
            for (Mechanism mechanism : mechanismList) {
                if (mechanism.match(ip)) {
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
            if (load) {
                loadList();
            }
        }
        
        private synchronized void loadList() {
            if (!mechanismList.isEmpty()) {
                loaded = true; // Temporário
            } else if (!loaded) {
                // Carregamento de lista.
                String expression = getExpression();
                if (!Character.isLetter(expression.charAt(0))) {
                    // Expressão com qualificador.
                    // Extrair qualificador.
                    expression = expression.substring(1);
                }
                String hostName;
                int indexDomain = expression.indexOf(':');
                int indexPrefix = expression.indexOf('/');
                if (indexDomain > 0 && indexPrefix > indexDomain) {
                    hostName = expression.substring(indexDomain + 1, indexPrefix);
                } else if (indexDomain > 0) {
                    hostName = expression.substring(indexDomain + 1);
                } else {
                    hostName = getHostname();
                }
                try {
                    Attributes attributesMX = Server.INITIAL_DIR_CONTEXT.getAttributes(
                            "dns:/" + hostName, new String[]{"MX"});
                    Attribute attributeMX = attributesMX.get("MX");
                    if (attributeMX != null) {
                        NamingEnumeration enumeration = attributeMX.getAll();
                        while (enumeration.hasMoreElements()) {
                            String hostAddress = (String) enumeration.next();
                            int indexSpace = hostAddress.indexOf(' ') + 1;
                            hostAddress = hostAddress.substring(indexSpace);
                            if (SubnetIPv4.isValidIPv4(hostAddress)) {
                                if (indexPrefix > 0) {
                                    hostAddress += expression.substring(indexPrefix);
                                }
                                mechanismList.add(new MechanismIPv4(hostAddress));
                            } else if (SubnetIPv6.isValidIPv6(hostAddress)) {
                                if (indexPrefix > 0) {
                                    hostAddress += expression.substring(indexPrefix);
                                }
                                mechanismList.add(new MechanismIPv6(hostAddress));
                            } else {
                                try {
                                    Attributes attributesA = Server.INITIAL_DIR_CONTEXT.getAttributes(
                                            "dns:/" + hostAddress, new String[]{"A"});
                                    Attribute attributeA = attributesA.get("A");
                                    if (attributeA != null) {
                                        for (int i = 0; i < attributeA.size(); i++) {
                                            String host4Address = (String) attributeA.get(i);
                                            if (SubnetIPv4.isValidIPv4(host4Address)) {
                                                if (indexPrefix > 0) {
                                                    host4Address += expression.substring(indexPrefix);
                                                }
                                                mechanismList.add(new MechanismIPv4(host4Address));
                                            }
                                        }
                                    }
                                } catch (NamingException ex) {
                                    // Não encontrou registro A para o MX.
                                }
                                if (indexPrefix == -1) {
                                    // Se não houver definição CIDR,
                                    // considerar também os endereços AAAA.
                                    // Isto não é um padrão SPF.
                                    try {
                                        Attributes attributesAAAA = Server.INITIAL_DIR_CONTEXT.getAttributes(
                                                "dns:/" + hostAddress, new String[]{"AAAA"});
                                        Attribute attributeAAAA = attributesAAAA.get("AAAA");
                                        if (attributeAAAA != null) {
                                            for (int i = 0; i < attributeAAAA.size(); i++) {
                                                String host6Address = (String) attributeAAAA.get(i);
                                                if (SubnetIPv6.isValidIPv6(host6Address)) {
                                                    mechanismList.add(new MechanismIPv6(host6Address));
                                                }
                                            }
                                        }
                                    } catch (NamingException ex) {
                                        // Não encontrou registro AAAA para o MX.
                                    }
                                }
                            }
                        }
                    }
                } catch (NamingException ex) {
                    // Não encontrou registro MX para o host.
                }
                loaded = true;
            }
        }
        
        @Override
        public boolean match(String ip) throws ProcessException {
            loadList();
            for (Mechanism mechanism : mechanismList) {
                if (mechanism.match(ip)) {
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
        
        @Override
        public synchronized boolean match(String ip) throws ProcessException {
            String expression = getExpression();
            String domain;
            int index = expression.indexOf(':');
            if (index > 0) {
                domain = "." + expression.substring(index + 1);
            } else {
                domain = "." + getHostname();
            }
            for (String hostname : SPF.getReverse(ip)) {
                if (hostname.endsWith(domain)) {
                    return true;
                }
            }
            return false;
        }
    }
    
    /**
     * Retorna o conjunto de hostnames que 
     * representam o DNS reverso do IP informado.
     * Apesar de geralmente haver apenas um reverso configurado,
     * é possível que haja mais de um pois é possível que haja
     * mais de um registro PTR e cada um deles apontando para o mesmo IP.
     * @param ip o IP a ser verificado.
     * @return o conjunto de reversos do IP informado.
     */
    private static TreeSet<String> getReverse(String ip) {
        TreeSet<String> reverseList = new TreeSet<String>();
        try {
            byte[] address1;
            String reverse;
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
                    for (char digit : hexPart.toCharArray()) {
                        reverse = digit + "." + reverse;
                    }
                }
            } else {
                throw new ProcessException("ERROR: DNS REVERSE");
            }
            try {
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
                            host = host.substring(0,host.length()-1);
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
                            for (int indexA = 0; indexA < attributeAAAA.size(); indexA++) {
                                String ipAAAA = (String) attributeAAAA.get(indexA);
                                byte[] address2 = SubnetIPv6.splitByte(ipAAAA);
                                if (Arrays.equals(address1, address2)) {
                                    reverseList.add("." + host);
                                    break;
                                }
                            }
                        }
                    } catch (NamingException ex) {
                        // Registro não encontrado.
                    }
                }
            } catch (InvalidAttributeIdentifierException ex) {
                // Registro não encontrado.
            }
        } catch (NamingException ex) {
            // Reverso não encontrado.
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
        
        @Override
        public boolean match(String ip) throws ProcessException {
            throw new ProcessException("ERROR: NOT IMPLEMENTED");
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
        
        private String getHostname() {
            String expression = getExpression();
            int index = expression.indexOf(':') + 1;
            return expression.substring(index);
        }
        
        public Qualifier getQualifierSPF(
                String ip, int deep, TreeSet<String> hostVisitedSet
                ) throws ProcessException {
            String host = getHostname();
            SPF spf = SPF.getSPF(host);
            if (spf == null) {
                return null;
            } else {
                return spf.getQualifier(ip, deep, hostVisitedSet);
            }
            
        }
        
        @Override
        public boolean match(String ip) throws ProcessException {
            throw new ProcessException("ERROR: FATAL ERROR"); // Não pode fazer o match direto.
        }
    }
    
    @Override
    public String toString() {
        return hostname;
    }
    
    /**
     * Mapa para cache dos registros SPF consultados.
     */
    private static final HashMap<String,SPF> SPF_MAP = new HashMap<String,SPF>();
    
    /**
     * Adiciona um registro SPF no mapa de cache.
     * @param spf o registro SPF para ser adocionado.
     */
    private static synchronized void addSPF(SPF spf) {
        SPF_MAP.put(spf.getHostname(), spf);
        SPF_CHANGED = true;
    }
    
    /**
     * Retorna o registro SPF do e-mail.
     * @param address o endereço de e-mail que deve ser consultado.
     * @return o registro SPF, se for encontrado.
     * @throws ProcessException se houver falha no processamento.
     */
    public static SPF getSPF(String address) throws ProcessException {
        String host = Domain.extractHost(address, false);
        SPF spf;
        if (SPF_MAP.containsKey(host)) {
            spf = SPF_MAP.get(host);
            if (spf.isRegistryExpired()) {
                // Atualiza o registro se ele for antigo demais.
                spf.refresh(false);
            }
        } else {
            spf = new SPF(host);
            addSPF(spf);
        }
        spf.queries++; // Incrementa o contador de consultas.
        return spf;
    }
    
    private static synchronized void removeSPF(String host) {
        if (SPF_MAP.remove(host) != null) {
            SPF_CHANGED = true;
        }
    }
    
    /**
     * Armazenamento de cache em disco.
     */
    public static synchronized void store() {
        if (SPF_CHANGED) {
            try {
                Server.logDebug("Storing spf.map...");
                FileOutputStream outputStream = new FileOutputStream("spf.map");
                try {
                    SerializationUtils.serialize(SPF_MAP, outputStream);
                    SPF_CHANGED = false;
                } finally {
                    outputStream.close();
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        if (COMPLAIN_CHANGED) {
            try {
                Server.logDebug("Storing complain.map...");
                FileOutputStream outputStream = new FileOutputStream("complain.map");
                try {
                    SerializationUtils.serialize(COMPLAIN_MAP, outputStream);
                    COMPLAIN_CHANGED = false;
                } finally {
                    outputStream.close();
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        if (DISTRIBUTION_CHANGED) {
            try {
                Server.logDebug("Storing distribution.map...");
                FileOutputStream outputStream = new FileOutputStream("distribution.map");
                try {
                    SerializationUtils.serialize(DISTRIBUTION_MAP, outputStream);
                    DISTRIBUTION_CHANGED = false;
                } finally {
                    outputStream.close();
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        if (PROVIDER_CHANGED) {
            try {
                Server.logDebug("Storing provider.set...");
                FileOutputStream outputStream = new FileOutputStream("provider.set");
                try {
                    SerializationUtils.serialize(PROVIDER_SET, outputStream);
                    PROVIDER_CHANGED = false;
                } finally {
                    outputStream.close();
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        if (GUESS_CHANGED) {
            try {
                Server.logDebug("Storing guess.map...");
                FileOutputStream outputStream = new FileOutputStream("guess.map");
                try {
                    SerializationUtils.serialize(GUESS_MAP, outputStream);
                    GUESS_CHANGED = false;
                } finally {
                    outputStream.close();
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    /**
     * Carregamento de cache do disco.
     */
    public static synchronized void load() {
        { // Carregamento do mapa SPF.
            Server.logDebug("Loading spf.map...");
            File file = new File("spf.map");
            if (file.exists()) {
                try {
                    HashMap<String,SPF> map;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        map = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    SPF_MAP.putAll(map);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }
        { // Carregamento do mapa de reclamações.
            Server.logDebug("Loading complain.map...");
            File file = new File("complain.map");
            if (file.exists()) {
                try {
                    HashMap<String,Complain> map;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        map = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    COMPLAIN_MAP.putAll(map);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }
        { // Carregamento do mapa de distribuição.
            Server.logDebug("Loading distribution.map...");
            File file = new File("distribution.map");
            if (file.exists()) {
                try {
                    HashMap<String,Distribution> map;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        map = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    DISTRIBUTION_MAP.putAll(map);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }
        { // Carregamento do conjunto de provedores de e-mail.
            Server.logDebug("Loading provider.set...");
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
                    PROVIDER_SET.addAll(set);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }
        { // Carregamento do mapa de palpites SPF.
            Server.logDebug("Loading guess.map...");
            File file = new File("guess.map");
            if (file.exists()) {
                try {
                    HashMap<String,String> map;
                    FileInputStream fileInputStream = new FileInputStream(file);
                    try {
                        map = SerializationUtils.deserialize(fileInputStream);
                    } finally {
                        fileInputStream.close();
                    }
                    GUESS_MAP.putAll(map);
                } catch (Exception ex) {
                    Server.logError(ex);
                }
            }
        }
    }
    
    private static final Semaphore BACKGROUND_SEMAPHORE = new Semaphore(1);
    
    public static void tryBackugroundRefresh() {
        // Evita que muitos processos fiquem 
        // presos aguardando a liberação do método.
        if (BACKGROUND_SEMAPHORE.tryAcquire()) {
            try {
                backgroundRefresh();
            } finally {
                BACKGROUND_SEMAPHORE.release();
            }
        }
    }
    
    
    public static synchronized void backgroundRefresh() {
        SPF spfMax = null;
        for (SPF spf : SPF_MAP.values()) {
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
                Server.logError(ex);
            }
        }
        SPF.store();
    }
    
    public static boolean heloMatchIP(String ip, String helo) {
        if (!Domain.containsDomain(helo)) {
            // o HELO não é um hostname válido.
            return false;
        } else if (SubnetIPv4.isValidIPv4(ip)) {
            try {
                Attributes attributes = Server.INITIAL_DIR_CONTEXT.getAttributes(
                        "dns:/" + helo, new String[]{"A"});
                Attribute attribute = attributes.get("A");
                if (attribute == null) {
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
                                return true;
                            }
                        }
                    }
                    return false;
                }
            } catch (NamingException ex) {
                // Não encontrou registro A para o host.
                return false;
            }
        } else if (SubnetIPv6.isValidIPv6(ip)) {
            try {
                Attributes attributes = Server.INITIAL_DIR_CONTEXT.getAttributes(
                        "dns:/" + helo, new String[]{"AAAA"});
                Attribute attribute = attributes.get("AAAA");
                if (attribute == null) {
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
                                return true;
                            }
                        }
                    }
                    return false;
                }
            } catch (NamingException ex) {
                // Não encontrou registro AAAA para o host.
                return false;
            }
        } else {
            // O parâmetro ip não é um IP válido.
            return false;
        }
    }
    
    /**
     * Processa a consulta e retorna o resultado.
     * @param query a expressão da consulta.
     * @return o resultado do processamento.
     */
    protected static String processSPF(String query) {
        try {
            String result = "";
            if (query.length() == 0) {
                result = "ERROR: QUERY\n";
            } else {
                StringTokenizer tokenizer = new StringTokenizer(query, " ");
                String firstToken = tokenizer.nextToken();
                if (firstToken.equals("SPAM") && tokenizer.countTokens() == 1) {
                    String ticket = tokenizer.nextToken();
                    SPF.addComplain(ticket);
                    result = "OK\n";
                } else if (firstToken.equals("HAM") && tokenizer.countTokens() == 1) {
                    String ticket = tokenizer.nextToken();
                    SPF.removeComplain(ticket);
                    result = "OK\n";
                } else if ((firstToken.equals("CHECK") && tokenizer.countTokens() == 3) || tokenizer.countTokens() == 2) {
                    try {
                        String ip;
                        if (firstToken.equals("CHECK")) {
                            ip = tokenizer.nextToken();
                        } else {
                            ip = firstToken;
                        }
                        String email = tokenizer.nextToken().toLowerCase();
                        String helo = tokenizer.nextToken().toLowerCase();
                        if (!SubnetIPv4.isValidIPv4(ip) && !SubnetIPv6.isValidIPv6(ip)) {
                            result = "ERROR: QUERY\n";
                        } else if (!Domain.containsDomain(email)) {
                            result = "ERROR: QUERY\n";
                        } else {
                            SPF spf = SPF.getSPF(email);
                            result = spf.getResult(ip);
                            TreeSet<String> tokenSet = new TreeSet<String>();
                            String ownerid;
//                            String owner_c;
                            if (result.equals("FAIL")) {
                                // Adicionar tokens quando FAIL.
                                // Criar auto-reclamação?
                            } else if (result.equals("PASS")) {
                                // Quando fo PASS, significa que o domínio 
                                // autorizou envio pelo IP, portanto o dono dele 
                                // é responsavel pelas mensagens.
                                String host = Domain.extractHost(email, true);
                                if (PROVIDER_SET.contains(host)) {
                                    // Listar apenas o remetente se o 
                                    // host for um provedor de e-mail.
                                    tokenSet.add(email);
                                } else {
                                    // Não é um provedor então
                                    // o domínio deve ser listado.
                                    tokenSet.add(host);
                                    tokenSet.add(Domain.extractDomain(email, true));
                                    if ((ownerid = Domain.getOwnerID(email)) != null) {
                                        tokenSet.add(ownerid);
                                    }
//                                    if ((owner_c = Domain.getOwnerC(email)) != null) {
//                                        tokenSet.add(owner_c);
//                                    }
                                }
                            } else if (SPF.heloMatchIP(ip, helo)) {
                                // Se o HELO apontar para o IP,
                                // então o dono do HELO é o responsável.
                                if (!helo.startsWith(".")) {
                                    helo = "." + helo;
                                }
                                tokenSet.add(helo);
                                tokenSet.add(Domain.extractDomain(helo, true));
                                if ((ownerid = Domain.getOwnerID(helo)) != null) {
                                    tokenSet.add(ownerid);
                                }
//                                if ((owner_c = Domain.getOwnerC(helo)) != null) {
//                                    tokenSet.add(owner_c);
//                                }
                            } else {
                                // Em qualquer outro caso,
                                // o responsável é o dono do IP.
                                if (SubnetIPv4.isValidIPv4(ip)) {
                                    // Formalizar notação IPv4.
                                    tokenSet.add(SubnetIPv4.correctIP(ip));
                                } else if (SubnetIPv6.isValidIPv6(ip)) {
                                    // Formalizar notação IPv6.
                                    tokenSet.add(SubnetIPv6.correctIP(ip));
                                }
                                if ((ownerid = Subnet.getOwnerID(ip)) != null) {
                                    tokenSet.add(ownerid);
                                }
//                                if ((owner_c = Subnet.getOwnerC(ip)) != null) {
//                                    tokenSet.add(owner_c);
//                                }
                            }
                            if (firstToken.equals("CHECK")) {
                                result += "\n";
                                TreeMap<String,Distribution> distributionMap = SPF.getDistributionMap(tokenSet);
                                for (String token : tokenSet) {
                                    float probability;
                                    Status status;
                                    String frequency;
                                    if (distributionMap.containsKey(token)) {
                                        Distribution distribution = distributionMap.get(token);
                                        probability = distribution.getMinSpamProbability();
                                        status = distribution.getStatus();
                                        frequency = distribution.getFrequencyLiteral();
                                    } else {
                                        probability = 0.0f;
                                        status = SPF.Status.WHITE;
                                        frequency = "undefined";
                                    }
                                    result += token + " " + frequency + " " + status.name() + " "
                                            + Server.DECIMAL_FORMAT.format(probability) + "\n";
                                }
                            } else {
                                String ticket;
                                if (tokenSet.isEmpty()) {
                                    // Não processar ticket quando não houver tokens.
                                    result += "\n";
                                } else if ((ticket = SPF.getTicket(tokenSet)) == null) {
                                    // Se não retornou ticket,
                                    // significa que pelo menos um token
                                    // do conjunto está em lista negra.
                                    result = "LISTED\n";
                                } else {
                                    // Anexando ticket ao resultado.
                                    result += " " + ticket + "\n";
                                    Server.logTicket(tokenSet);
                                }
                            }
                        }
                    } catch (ProcessException ex) {
                        if (ex.getMessage().equals("ERROR: HOST NOT FOUND")) {
                            // Considerar FAIL sempre que o host não existir.
                            return "FAIL";
                        } else {
                            throw ex;
                        }
                    }
                } else {
                    result = "ERROR: QUERY\n";
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
    
    /**
     * Constante de formatação da data no ticket.
     * Baseado no padrão ISO 8601
     * 
     * Um objeto SimpleDateFormat não é thread safety,
     * portanto é necessário utilizar sincronismo
     * nos métodos que o utilizam.
     */
    private static final SimpleDateFormat FORMAT_DATE_TICKET = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSSZ");
    
    public static synchronized String getTicket(TreeSet<String> tokenSet) throws ProcessException {
        if (isBlacklisted(tokenSet)) {
            // Representa ameaça.
            // Não gerar ticket.
            return null;
        } else {
            // Não representa ameaça.
            String ticket = FORMAT_DATE_TICKET.format(new Date());
            for (String token : tokenSet) {
                ticket += " " + token;
            }
            return Server.encrypt(ticket);
        }
    }
    
    private static synchronized Date getTicketDate(String date) throws ProcessException {
        try {
            return FORMAT_DATE_TICKET.parse(date);
        } catch (ParseException ex) {
            throw new ProcessException("ERROR: INVALID TICKET", ex);
        }
    }
    
    /**
     * Timer que controla as reclamações.
     */
    private static final Timer COMPLAIN_TIMER = new Timer("TimerComplain");
    
    public static void cancelTimer() {
        COMPLAIN_TIMER.cancel();
    }
    
    static {
        // Agenda processamento de reclamações vencidas.
        COMPLAIN_TIMER.schedule(
                new TimerTask() {
                    @Override
                    public synchronized void run() {
                        LinkedList<String> expiredTicket = new LinkedList<String>();
                        // Verificar reclamações vencidas.
                        for (String ticket : COMPLAIN_MAP.keySet()) {
                            Complain complain = COMPLAIN_MAP.get(ticket);
                            if (complain.isExpired7()) {
                                complain.removeComplains();
                                expiredTicket.add(ticket);
                            }
                        }
                        // Remover todos os tickets processados.
                        for (String ticket : expiredTicket) {
                            COMPLAIN_MAP.remove(ticket);
                            COMPLAIN_CHANGED = true;
                        }
                        // Apagar todas as distribuições vencidas.
                        dropExpiredDistribution();
                    }
                }, 3600000, 3600000 // Frequência de 1 hora.
                );
    }
    
    /**
     * Mapa de reclamações com seus respectivos tickets.
     */
    private static HashMap<String,Complain> COMPLAIN_MAP = new HashMap<String,Complain>();
    
    /**
     * Flag que indica se o cache de reclamações foi modificado.
     */
    private static boolean COMPLAIN_CHANGED = false;
    
    /**
     * Adiciona uma nova reclamação de SPAM.
     * @param ticket o ticket da mensagem original.
     * @throws ProcessException se houver falha no processamento do ticket.
     */
    public synchronized static void addComplain(String ticket) throws ProcessException {
        if (!COMPLAIN_MAP.containsKey(ticket)) {
            COMPLAIN_MAP.put(ticket, new Complain(ticket));
            COMPLAIN_CHANGED = true;
        }
    }
    
    /**
     * Remove uma nova reclamação de SPAM.
     * @param ticket o ticket da mensagem original.
     * @throws ProcessException se houver falha no processamento do ticket.
     */
    public synchronized static void removeComplain(String ticket) {
        Complain complain = COMPLAIN_MAP.remove(ticket);
        if (complain != null) {
            complain.removeComplains();
            COMPLAIN_CHANGED = true;
        }
    }
    
    /**
     * Classe que representa uma reclamação.
     * Possui mecanismo de vencimento da reclamação.
     */
    private static final class Complain implements Serializable {
        
        private static final long serialVersionUID = 1L;
        
        private final Date date;
        private final TreeSet<String> tokenSet = new TreeSet<String>();
        
        public Complain(String ticket) throws ProcessException {
            String complain = Server.decrypt(ticket);
            int index = complain.indexOf(' ');
            date = getTicketDate(complain.substring(0, index));
            if (isExpired3()) {
                // Ticket vencido com mais de 3 dias.
                throw new ProcessException("ERROR: TICKET EXPIRED");
            } else {
                StringTokenizer tokenizer = new StringTokenizer(complain.substring(index+1), " ");
                while (tokenizer.hasMoreTokens()) {
                    String token = tokenizer.nextToken();
                    getDistribution(token, true).addSpam();
                    tokenSet.add(token);
                }
                Server.logSpamSPF(tokenSet);
            }
        }
        
        public boolean isExpired3() {
            return System.currentTimeMillis() - date.getTime() > 259200000;
        }
        
        public boolean isExpired7() {
            return System.currentTimeMillis() - date.getTime() > 604800000;
        }
        
        public void removeComplains() {
            Server.logHamSPF(tokenSet);
            // Retira todas as reclamações.
            while (!tokenSet.isEmpty()) {
                String token = tokenSet.pollFirst();
                Distribution distribution = getDistribution(token, false);
                if (distribution != null) {
                    distribution.removeSpam();
                }
            }
        }
        
        @Override
        public String toString() {
            return FORMAT_DATE_TICKET.format(date);
        }
    }
    
    /**
     * Conjunto de provedores notórios de e-mail.
     */
    private static TreeSet<String> PROVIDER_SET = new TreeSet<String>();
    
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean PROVIDER_CHANGED = false;
    
    public synchronized static void addProvider(String domain) throws ProcessException {
        domain = Domain.extractHost(domain, false);
        if (!Domain.containsDomain(domain)) {
            throw new ProcessException("ERROR: PROVIDER INVALID");
        } else {
            domain = "@" + domain;
            if (PROVIDER_SET.add(domain)) {
                PROVIDER_CHANGED = true;
            }
        }
    }
    
    public synchronized static void dropExpiredDistribution() {
        TreeSet<String> distributionKeySet = new TreeSet<String>();
        distributionKeySet.addAll(DISTRIBUTION_MAP.keySet());
        for (String token : distributionKeySet) {
            Distribution distribution = DISTRIBUTION_MAP.get(token);
            if (distribution.hasLastQuery() && distribution.isExpired14()) {
                dropDistribution(token);
            }
        }
    }
    
    public synchronized static void dropDistribution(String token) {
        if (DISTRIBUTION_MAP.remove(token) != null) {
            DISTRIBUTION_CHANGED = true;
        }
    }
    
    /**
     * Mapa de distribuição binomial dos tokens encontrados.
     */
    private static HashMap<String,Distribution> DISTRIBUTION_MAP = new HashMap<String,Distribution>();
    
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean DISTRIBUTION_CHANGED = false;
    
    private static boolean isBlacklisted(TreeSet<String> tokenSet) {
        boolean blacklisted = false;
        for (String token : tokenSet) {
            Distribution distribution = getDistribution(token, false);
            if (distribution == null) {
                // Distribuição não encontrada.
                // Considerar que não está listado.
            } else if (distribution.isBlacklisted()) {
                blacklisted = true;
            }
        }
        return blacklisted;
    }
    
    /**
     * Retorna uma distribuição binomial do token informado.
     * @param token o token cuja distribuição deve ser retornada.
     * @return uma distribuição binomial do token informado.
     */
    private synchronized static Distribution getDistribution(String token, boolean create) {
        Distribution distribution;
        if (DISTRIBUTION_MAP.containsKey(token)) {
            distribution = DISTRIBUTION_MAP.get(token);
            if (distribution.isExpired7()) {
                distribution.reset();
            }
        } else if (create) {
            distribution = new Distribution();
            DISTRIBUTION_MAP.put(token, distribution);
        } else {
            distribution = null;
        }
        return distribution;
    }
    
    public synchronized static TreeMap<String,Distribution> getDistributionMap() {
        TreeMap<String,Distribution> distributionMap = new TreeMap<String,Distribution>();
        for (String token : DISTRIBUTION_MAP.keySet()) {
            Distribution distribution = DISTRIBUTION_MAP.get(token);
            distributionMap.put(token, distribution);
        }
        return distributionMap;
    }
    
    public synchronized static TreeMap<String,Distribution> getDistributionMap(TreeSet<String> tokenSet) {
        TreeMap<String,Distribution> distributionMap = new TreeMap<String,Distribution>();
        for (String token : tokenSet) {
            if (DISTRIBUTION_MAP.containsKey(token)) {
                Distribution distribution = DISTRIBUTION_MAP.get(token);
                distributionMap.put(token, distribution);
            }
        }
        return distributionMap;
    }
    
    /**
     * Enumeração do status da distribuição.
     */
    public enum Status implements Serializable {
        WHITE, // Whitelisted
        GRAY, // Graylisted
        BLACK; // Blacklisted
    }
    
    /**
     * Classe que representa a distribuição binomial entre SPAM e HAM.
     * O valor máximo é 255. 
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
            DISTRIBUTION_CHANGED = true;
        }
        
        public boolean isExpired7() {
            return System.currentTimeMillis() - lastQuery > 604800000;
        }
        
        public boolean isExpired14() {
            return System.currentTimeMillis() - lastQuery > 604800000 * 2;
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
                DISTRIBUTION_CHANGED = true;
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
         * Máquina de estados para listar em um pico e
         * retirar a listagem somente quando o total 
         * cair consideravelmente após este pico.
         * @return o status atual da distribuição.
         */
        public synchronized Status getStatus() {
            float[] probability = getSpamProbability();
            float min = probability[0];
            float max = probability[2];
            if (max == 0.0f) {
                status = Status.WHITE;
            } else if (min > 0.125f) {
                status = Status.BLACK;
            } else if (status == Status.GRAY && min > 0.0625f) {
                status = Status.BLACK;
            } else if (status == Status.BLACK && max < 0.0625f) {
                status = Status.GRAY;
            }
            return status;
        }
        
        /**
         * Verifica se o estado atual da distribuição é blacklisted.
         * @return verdadeiro se o estado atual da distribuição é blacklisted.
         */
        public boolean isBlacklisted() {
            addQuery();
            return getStatus() == Status.BLACK;
        }
        
        public synchronized void removeSpam() {
            if (complain > 0) {
                complain--;
                DISTRIBUTION_CHANGED = true;
            }
        }
        
        public synchronized void addSpam() {
            if (complain < Integer.MAX_VALUE) {
                complain++;
                lastComplain = System.currentTimeMillis();
                DISTRIBUTION_CHANGED = true;
            }
        }
        
        @Override
        public String toString() {
            return Float.toString(getMinSpamProbability());
        }
    }
}
