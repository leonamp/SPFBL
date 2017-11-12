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
import java.util.Date;
import java.util.HashMap;
import java.util.TreeSet;
import java.util.regex.Pattern;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Representa o registro de dono de um resultado WHOIS.
 * 
 * A chave primária dos registros é o atributo ownerid.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Owner implements Serializable, Comparable<Owner> {
    
    private static final long serialVersionUID = 1L;
    
    private String owner; // Nome do dono.
    private final String ownerid; // Identificação do dono.
    private String responsible; // Responsável pelo registro.
    private String country; // País onde o dono foi registrado.
    private String owner_c; // Código do dono.
    private Date created; // Data de criação do registro.
    private Date changed; // Data da alteração do registro.
    private String provider; // Provedor de responsável.
    
    /**
     * Lista dos dominios registrados.
     */
    private final ArrayList<String> domainList = new ArrayList<String>();
    
    private String server = null; // Servidor onde a informação do registro pode ser encontrada.
    private long lastRefresh = 0; // Última vez que houve atualização do registro em milisegundos.
    private boolean reduced = false; // Diz se a última consulta foi reduzida.
    private int queries = 1; // Contador de consultas.
    
    private static int REFRESH_TIME = 84;  // Prazo máximo que o registro deve permanecer em cache em dias.
    
    /**
     * Formatação padrão dos campos de data do WHOIS.
     */
    private static final SimpleDateFormat DATE_FORMATTER = new SimpleDateFormat("yyyyMMdd");
    
    /**
     * Atualiza o tempo de expiração do registro de domínio.
     * @param time tempo em dias que os registros de domíno devem ser atualizados.
     */
    protected static void setRefreshTime(int time) {
        REFRESH_TIME = time;
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
     * Verifica se a expressão é um CPNJ ou CPF.
     * @param id a identificação a ser verificada.
     * @return verdadeiro se a expressão é um CPNJ ou CPF.
     */
    public static boolean isOwnerID(String id) {
        return Pattern.matches(
                "^([0-9]{3}\\.[0-9]{3}\\.[0-9]{3}-[0-9]{2})"
                + "|([0-9]{2,3}\\.[0-9]{3}\\.[0-9]{3}/[0-9]{4}-[0-9]{2})$", id
                );
    }
    
    /**
     * Verifica se a expressão é um CPNJ.
     * @param id a identificação a ser verificada.
     * @return verdadeiro se a expressão é um CPNJ.
     */
    public static boolean isOwnerCNPJ(String id) {
        return Pattern.matches(
                "^([0-9]{2,3}\\.[0-9]{3}\\.[0-9]{3}/[0-9]{4}-[0-9]{2})$", id
                );
    }
    
    /**
     * Verifica se a expressão é um CPF.
     * @param id a identificação a ser verificada.
     * @return verdadeiro se a expressão é um CPF.
     */
    public static boolean isOwnerCPF(String id) {
        return Pattern.matches(
                "^([0-9]{3}\\.[0-9]{3}\\.[0-9]{3}-[0-9]{2})$", id
                );
    }
    
    /**
     * Intancia um novo registro de domínio.
     * @param result o resultado do WHOIS.
     * @throws QueryException se houver alguma falha da atualização do registro.
     */
    private Owner(String id) throws ProcessException {
        this.ownerid = normalizeID(id);
        this.refresh();
    }
    
    public static String normalizeID(String id) {
        if (id == null) {
            return null;
        } else if (id.length() == 0) {
            return null;
        } else if (Pattern.matches("^[0-9]{3}\\.[0-9]{3}\\.[0-9]{3}-[0-9]{2}$", id)) {
            return id;
        } else if (Pattern.matches("^[0-9]{3}\\.[0-9]{3}\\.[0-9]{3}/[0-9]{4}-[0-9]{2}$", id)) {
            return id;
        } else if (Pattern.matches("^[0-9]{2}\\.[0-9]{3}\\.[0-9]{3}/[0-9]{4}-[0-9]{2}$", id)) {
            return "0" + id;
        } else {
            return null;
        }
    }
    
    private boolean refresh() throws ProcessException {
        server = Server.WHOIS_BR; // Temporário até final de transição.
        String result = Server.whoisID(ownerid, server);
        String ownerResult = refresh(result);
        return ownerid.equals(ownerResult);
    }
    
    /**
     * Atualiza os campos do registro com resultado do WHOIS.
     * @param result o resultado do WHOIS.
     * @return o ownerid real apresentado no resultado do WHOIS.
     * @throws QueryException se houver alguma falha da atualização do registro.
     */
    private String refresh(String result) throws ProcessException {
        try {
            boolean reducedLocal = false;
            String owneridResult = null;
            BufferedReader reader = new BufferedReader(new StringReader(result));
            try {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.startsWith("owner:")) {
                        int index = line.indexOf(':') + 1;
                        owner = line.substring(index).trim();
                    } else if (line.startsWith("ownerid:")) {
                        int index = line.indexOf(':') + 1;
                        owneridResult = line.substring(index).trim();
                    } else if (line.startsWith("responsible:")) {
                        int index = line.indexOf(':') + 1;
                        responsible = line.substring(index).trim();
                    } else if (line.startsWith("country:")) {
                        int index = line.indexOf(':') + 1;
                        country = line.substring(index).trim();
                    } else if (line.startsWith("owner-c:")) {
                        int index = line.indexOf(':') + 1;
                        owner_c = line.substring(index).trim();
                    } else if (line.startsWith("domain:")) {
                        int index = line.indexOf(':') + 1;
                        String domain = line.substring(index).trim();
                        domainList.add(domain);
                    } else if (line.startsWith("created:")) {
                        int index = line.indexOf(':') + 1;
                        String valor = line.substring(index).trim();
                        if (valor.startsWith("before ")) {
                            index = line.indexOf(' ');
                            valor = valor.substring(index);
                        }
                        created = DATE_FORMATTER.parse(valor);
                    } else if (line.startsWith("changed:")) {
                        int index = line.indexOf(':') + 1;
                        changed = DATE_FORMATTER.parse(line.substring(index).trim());
                    } else if (line.startsWith("provider:")) {
                        int index = line.indexOf(':') + 1;
                        provider = line.substring(index).trim();
                    } else if (line.startsWith("nic-hdl-br:")) {
                        int index = line.indexOf(':') + 1;
                        String nic_hdl_br = line.substring(index).trim();
                        line = reader.readLine().trim();
                        index = line.indexOf(':') + 1;
                        String person = line.substring(index).trim();
                        line = reader.readLine().trim();
                        index = line.indexOf(':') + 1;
                        String e_mail;
                        if (reducedLocal) {
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
                        throw new ProcessException("ERROR: OWNER NOT FOUND");
                    } else if (line.startsWith("% Permission denied.")) {
                        throw new ProcessException("ERROR: WHOIS DENIED");
                    } else if (line.startsWith("% Permissão negada.")) {
                        throw new ProcessException("ERROR: WHOIS DENIED");
                    } else if (line.startsWith("% Maximum concurrent connections limit exceeded")) {
                        throw new ProcessException("ERROR: WHOIS CONCURRENT");
                    } else if (line.startsWith("% Query rate limit exceeded. Reduced information.")) {
                        // Informação reduzida devido ao estouro de limite de consultas.
                        Server.removeWhoisQueryHour();
                        reducedLocal = true;
                    } else if (line.startsWith("% Query rate limit exceeded")) {
                        // Restrição total devido ao estouro de limite de consultas.
                        Server.removeWhoisQueryDay();
                        throw new ProcessException("ERROR: WHOIS QUERY LIMIT");
                    } else if (line.length() > 0 && Character.isLetter(line.charAt(0))) {
                        Server.logError("Linha não reconhecida: " + line);
                    }
                }
            } finally {
                reader.close();
            }
            if (owneridResult == null) {
                throw new ProcessException("ERROR: OWNER NOT FOUND");
            } else {
                this.lastRefresh = System.currentTimeMillis();
                this.reduced = reducedLocal;
                this.queries = 1;
                // Atualiza flag de atualização.
                OWNER_CHANGED = true;
                // Retorna o ownerid real indicado pelo WHOIS.
                return owneridResult;
            }
        } catch (ProcessException ex) {
            throw ex;
        } catch (Exception ex) {
            Server.logError(ex);
            throw new ProcessException("ERROR: PARSING", ex);
        }
    }
    
    public Handle getOwner() {
        return Handle.getHandle(owner_c);
    }
    
    /**
     * Retorna o valor de um campo do registro ou o valor de uma função.
     * @param key o campo do registro cujo valor deve ser retornado.
     * @return o valor de um campo do registro ou o valor de uma função.
     * @throws ProcessException se houver falha no processamento.
     */
    public String get(String key, boolean updated) throws ProcessException {
        if (key.equals("owner")) {
            return owner;
        } else if (key.equals("ownerid")) {
            return ownerid;
        } else if (reduced && updated) {
            // Ultima consulta com informação reduzida.
            // Demais campos estão comprometidos.
            throw new ProcessException("ERROR: WHOIS QUERY LIMIT");
        } else if (key.equals("responsible")) {
            return responsible;
        } else if (key.equals("country")) {
            return country;
        } else if (key.equals("owner-c")) {
            return owner_c;
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
        } else if (key.equals("provider")) {
            return provider;
        } else if (key.equals("domain")) {
            return domainList.toString();
        } else if (key.startsWith("owner-c/")) {
            int index = key.indexOf('/') + 1;
            key = key.substring(index);
            Handle owner = getOwner();
            if (owner == null) {
                return null;
            } else {
                return owner.get(key);
            }
        } else if (key.startsWith("domain/")) {
            int index = key.indexOf('/') + 1;
            key = key.substring(index);
            TreeSet<String> resultSet = new TreeSet<String>();
            for (String domainName : domainList) {
                Domain domain = Domain.getDomain(domainName);
                if (domain == null) {
                    return null;
                } else {
                    String result = domain.get(key, updated);
                    resultSet.add(domainName + "=" + result);
                }
            }
            return resultSet.toString();
        } else {
            return null;
        }
    }
    
    public static synchronized HashMap<String,Owner> getMap() {
        HashMap<String,Owner> map = new HashMap<String,Owner>();
        map.putAll(MAP);
        return map;
    }
    
    /**
     * Armazenamento de cache em disco.
     */
    public static void store() {
        if (OWNER_CHANGED) {
            try {
//                Server.logTrace("storing owner.map");
                long time = System.currentTimeMillis();
                HashMap<String,Owner> map = getMap();
                File file = new File("./data/owner.map");
                FileOutputStream outputStream = new FileOutputStream(file);
                try {
                    SerializationUtils.serialize(map, outputStream);
                    // Atualiza flag de atualização.
                    OWNER_CHANGED = false;
                } finally {
                    outputStream.close();
                }
                Server.logStore(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static synchronized Owner put(String key, Owner owner) {
        return MAP.put(key, owner);
    }
    
    /**
     * Carregamento de cache do disco.
     */
    public static void load() {
        long time = System.currentTimeMillis();
        File file = new File("./data/owner.map");
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
                    if (value instanceof Owner) {
                        Owner owner = (Owner) value;
                        put(key, owner);
                    }
                }
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    /**
     * Mapa de domínios com busca de hash O(1).
     */
    private static final HashMap<String,Owner> MAP = new HashMap<>();
    
    /**
     * Remove registro de domínio do cache.
     * @param id a identificação do dono que deve ser removido.
     * @return o registro de dono removido, se existir.
     * @throws ProcessException se houver falha no processamento.
     */
    public static synchronized Owner removeOwner(String id) throws ProcessException {
        String key = normalizeID(id);
        Owner owner = MAP.remove(key);
        if (owner != null) {
            // Atualiza flag de atualização.
            OWNER_CHANGED = true;
        }
        return owner;
    }
    
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean OWNER_CHANGED = false;
    
    /**
     * Atualiza o registro de domínio de um determinado host.
     * @param id a identificação do dono que deve ser atualizado.
     * @throws ProcessException se houver falha no processamento.
     */
    public static synchronized void refreshOwner(String id) throws ProcessException {
        String key = normalizeID(id);
        if (key != null) {
            // Busca eficiente O(1).
            if (MAP.containsKey(key)) {
                // Owner encontrado.
                Owner owner = MAP.get(key);
                // Atualizando campos do registro.
                if (!owner.refresh()) {
                    // Owner real do resultado WHOIS não bate com o registro.
                    // Apagando registro de dono do cache.
                    if (MAP.remove(owner.getOwnerID()) != null) {
                        // Atualiza flag de atualização.
                        OWNER_CHANGED = true;
                    }
                    // Segue para nova consulta.
                }
            }
            // Não encontrou o dono em cache.
            // Selecionando servidor da pesquisa WHOIS.
            String server = Server.WHOIS_BR;
            // Realizando a consulta no WHOIS.
            Owner owner = new Owner(key);
            owner.server = server; // Temporário até final de transição.
            // Adicinando registro em cache.
            MAP.put(owner.getOwnerID(), owner);
            OWNER_CHANGED = true;
        }
    }
    
    /**
     * Retorna o registro de domínio de um determinado host.
     * @param id a identificação do dono que deve ser retornado.
     * @return o registro de domínio de um determinado host.
     * @throws ProcessException se houver falha no processamento.
     */
    public static synchronized Owner getOwner(String id) throws ProcessException {
        String key = normalizeID(id);
        if (key == null) {
            return null;
        } else {
            // Busca eficiente O(1).
            if (MAP.containsKey(key)) {
                // Owner encontrado.
                Owner owner = MAP.get(key);
                owner.queries++;
                if (owner.isRegistryExpired()) {
                    // Registro desatualizado.
                    // Atualizando campos do registro.
                    if (owner.refresh()) {
                        // Owner real do resultado WHOIS bate com o registro.
                        return owner;
                    } else if (MAP.remove(owner.getOwnerID()) != null) {
                        // Owner real do resultado WHOIS não bate com o registro.
                        OWNER_CHANGED = true;
                        // Segue para nova consulta.
                    }
                } else {
                    // Registro atualizado.
                    return owner;
                }
            }
            // Não encontrou o dominio em cache.
            // Selecionando servidor da pesquisa WHOIS.
            String server = Server.WHOIS_BR;
            // Realizando a consulta no WHOIS.
            Owner owner = new Owner(key);
            owner.server = server; // Temporário até final de transição.
            // Adicinando registro em cache.
            MAP.put(owner.getOwnerID(), owner);
            OWNER_CHANGED = true;
            return owner;
        }
    }
    
    /**
     * Retorna a identificação do dono.
     * @return a identificação do dono.
     */
    public String getOwnerID() {
        return ownerid;
    }
    
    @Override
    public int hashCode() {
        return ownerid.hashCode();
    }
    
    @Override
    public boolean equals(Object other) {
        if (other instanceof Owner) {
            return equals((Owner) other);
        } else {
            return false;
        }
    }
    
    /**
     * Verifica se o registro atual é o mesmo de outro.
     * @param other o outro registro a ser comparado.
     * @return verdadeiro se o registro passado é igual ao atual.
     */
    public boolean equals(Owner other) {
        if (other == null) {
            return false;
        } else {
            return this.ownerid.equals(other.ownerid);
        }
    }
    
    @Override
    public int compareTo(Owner other) {
        return this.owner.compareTo(other.owner);
    }
    
    @Override
    public String toString() {
        return owner;
    }
}
