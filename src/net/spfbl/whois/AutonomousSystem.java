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
import java.util.Date;
import java.util.HashMap;
import java.util.TreeSet;
import org.apache.commons.lang3.SerializationUtils;

/**
 *
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class AutonomousSystem implements Serializable, Comparable<AutonomousSystem>  {
    
    private static final long serialVersionUID = 1L;
    
    private final String aut_num;
    private String owner;
    private String ownerid;
    private String responsible;
    private String country;
    private String owner_c;
    private String routing_c;
    private String abuse_c;
    private Date created;
    private Date changed;

    /**
     * Lista dos blocos alocados ao AS.
     */
    private final TreeSet<String> inetnumSet = new TreeSet<String>();
    
    private final String server; // Servidor onde a informação do AS pode ser encontrada.
    private long lastRefresh = 0; // Última vez que houve atualização do registro em milisegundos.
    private boolean reduced = false; // Diz se a última consulta foi reduzida.
    private int queries = 1; // Contador de consultas.
    
    private static int REFRESH_TIME = 84;  // Prazo máximo que o registro deve permanecer em cache em dias.
    
    /**
     * Formatação padrão dos campos de data do WHOIS.
     */
    private static final SimpleDateFormat DATE_FORMATTER = new SimpleDateFormat("yyyyMMdd");
    
    /**
     * Atualiza o tempo de expiração do registro de AS.
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
     * Verifica se o registro atual está quase expirando.
     * @return verdadeiro se o registro atual está quase expirando.
     */
    public boolean isRegistryAlmostExpired() {
        long expiredTime = (System.currentTimeMillis() - lastRefresh) / Server.DAY_TIME;
        return expiredTime > (2 * REFRESH_TIME / 3); // Dois terços antes da expiração.
    }
    
    private AutonomousSystem(String aut_num, String server) throws ProcessException {
        this.aut_num = aut_num;
        this.server = server;
        refresh();
    }
    
    private void refresh() throws ProcessException {
        String result = Server.whois(aut_num, server);
        refresh(result);
        // Atualiza flag de atualização.
        AS_CHANGED = true;
    }
    
    /**
     * Atualiza os campos do registro com resultado do WHOIS.
     * @param result o resultado do WHOIS.
     * @return o domínio real apresentado no resultado do WHOIS.
     * @throws QueryException se houver alguma falha da atualização do registro.
     */
    private void refresh(String result) throws ProcessException {
        try {
            boolean reducedLocal = false;
            String autnumResult = null;
            BufferedReader reader = new BufferedReader(new StringReader(result));
            try {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.startsWith("aut-num:")) {
                        int index = line.indexOf(':') + 1;
                        autnumResult = line.substring(index).trim();
                    } else if (line.startsWith("owner:")) {
                        int index = line.indexOf(':') + 1;
                        owner = line.substring(index).trim();
                    } else if (line.startsWith("ownerid:")) {
                        int index = line.indexOf(':') + 1;
                        ownerid = line.substring(index).trim();
                    } else if (line.startsWith("responsible:")) {
                        int index = line.indexOf(':') + 1;
                        responsible = line.substring(index).trim();
                    } else if (line.startsWith("country:")) {
                        int index = line.indexOf(':') + 1;
                        country = line.substring(index).trim();
                    } else if (line.startsWith("owner-c:")) {
                        int index = line.indexOf(':') + 1;
                        owner_c = line.substring(index).trim();
                    } else if (line.startsWith("routing-c:")) {
                        int index = line.indexOf(':') + 1;
                        routing_c = line.substring(index).trim();
                    } else if (line.startsWith("abuse-c:")) {
                        int index = line.indexOf(':') + 1;
                        abuse_c = line.substring(index).trim();
                    } else if (line.startsWith("inetnum:")) {
                        int index = line.indexOf(':') + 1;
                        String inetnum = line.substring(index).trim();
                        inetnumSet.add(inetnum);
                    } else if (line.startsWith("created:")) {
                        int index = line.indexOf(':') + 1;
                        String valor = line.substring(index).trim();
                        created = DATE_FORMATTER.parse(valor);
                    } else if (line.startsWith("changed:")) {
                        int index = line.indexOf(':') + 1;
                        String valor = line.substring(index).trim();
                        changed = DATE_FORMATTER.parse(valor);
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
                        throw new ProcessException("ERROR: DOMAIN NOT FOUND");
                    } else if (line.startsWith("% release process: waiting")) {
                        throw new ProcessException("ERROR: WAITING");
                    } else if (line.startsWith("% reserved:    CG")) {
                        throw new ProcessException("ERROR: RESERVED");
                    } else if (line.startsWith("% Maximum concurrent connections limit exceeded")) {
                        throw new ProcessException("ERROR: WHOIS CONCURRENT");
                    } else if (line.startsWith("% Permission denied.")) {
                        throw new ProcessException("ERROR: WHOIS DENIED");
                    } else if (line.startsWith("% Permissão negada.")) {
                        throw new ProcessException("ERROR: WHOIS DENIED");
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
            if (autnumResult == null) {
                throw new ProcessException("ERROR: AS NOT FOUND");
            } else if (!autnumResult.equals(aut_num)) {
                throw new ProcessException("ERROR: PARSING");
            } else {
                this.lastRefresh = System.currentTimeMillis();
                this.reduced = reducedLocal;
                this.queries = 1;
                // Atualiza flag de atualização.
                AS_CHANGED = true;
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
    
    public Handle getRouting() {
        return Handle.getHandle(routing_c);
    }
    
    public Handle getAbuse() {
        return Handle.getHandle(abuse_c);
    }
    
    /**
     * Retorna o valor de um campo do registro ou o valor de uma função.
     * @param key o campo do registro cujo valor deve ser retornado.
     * @return o valor de um campo do registro ou o valor de uma função.
     * @throws ProcessException se houver falha no processamento.
     */
    public String get(String key) throws ProcessException {
        if (key.equals("aut_num")) {
            return aut_num;
        } else if (key.equals("owner")) {
            return owner;
        } else if (reduced) {
            // Ultima consulta com informação reduzida.
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
        } else if (key.equals("routing-c")) {
            return routing_c;
        } else if (key.equals("abuse-c")) {
            return abuse_c;
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
        } else if (key.equals("inetnum")) {
            return inetnumSet.toString();
        } else if (key.startsWith("owner-c/")) {
            int index = key.indexOf('/') + 1;
            key = key.substring(index);
            Handle owner = getOwner();
            if (owner == null) {
                return null;
            } else {
                return owner.get(key);
            }
        } else if (key.startsWith("routing-c/")) {
            int index = key.indexOf('/') + 1;
            key = key.substring(index);
            Handle routing = getRouting();
            if (routing == null) {
                return null;
            } else {
                return routing.get(key);
            }
        } else if (key.startsWith("abuse-c/")) {
            int index = key.indexOf('/') + 1;
            key = key.substring(index);
            Handle abuse = getAbuse();
            if (abuse == null) {
                return null;
            } else {
                return abuse.get(key);
            }
        } else {
            return null;
        }
    }
    
    public static synchronized HashMap<String,AutonomousSystem> getMap() {
        HashMap<String,AutonomousSystem> map = new HashMap<String,AutonomousSystem>();
        map.putAll(MAP);
        return map;
    }
    
    /**
     * Armazenamento de cache em disco.
     */
    public static void store() {
        if (AS_CHANGED) {
            try {
//                Server.logTrace("storing as.map");
                long time = System.currentTimeMillis();
                HashMap<String,AutonomousSystem> map = getMap();
                File file = new File("./data/as.map");
                FileOutputStream outputStream = new FileOutputStream(file);
                try {
                    SerializationUtils.serialize(map, outputStream);
                    // Atualiza flag de atualização.
                    AS_CHANGED = false;
                } finally {
                    outputStream.close();
                }
                Server.logStore(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static synchronized AutonomousSystem put(String key, AutonomousSystem handle) {
        return MAP.put(key, handle);
    }
    
    /**
     * Carregamento de cache do disco.
     */
    public static void load() {
        long time = System.currentTimeMillis();
        File file = new File("./data/as.map");
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
                    if (value instanceof AutonomousSystem) {
                        AutonomousSystem as = (AutonomousSystem) value;
                        put(key, as);
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
    private static final HashMap<String,AutonomousSystem> MAP = new HashMap<String,AutonomousSystem>();
    
//    /**
//     * Adciiona o registro de domínio no cache.
//     * @param as o as que deve ser adicionado.
//     */
//    private static synchronized void addAutonomousSystem(AutonomousSystem as) {
//        MAP.put(as.getNumber(), as);
//        // Atualiza flag de atualização.
//        AS_CHANGED = true;
//    }
    
//    /**
//     * Remove o registro de domínio do cache.
//     * @param as o as que deve ser removido.
//     */
//    private static synchronized void removeAutonomousSystem(AutonomousSystem as) {
//        if (MAP.remove(as.getNumber()) != null) {
//            // Atualiza flag de atualização.
//            AS_CHANGED = true;
//        }
//    }
    
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean AS_CHANGED = false;
    
    /**
     * Retorna o registro de AS de um determinado número.
     * @param number o número cujo registro de AS deve ser retornado.
     * @param server o servidor WHOIS que tem a informação.
     * @return o registro de AS de um determinado número.
     * @throws ProcessException se houver falha no processamento.
     */
    public static synchronized AutonomousSystem getAS(String number,
            String server) throws ProcessException {
        // Busca eficiente O(1).
        if (MAP.containsKey(number)) {
            // Domínio encontrado.
            AutonomousSystem as = MAP.get(number);
            as.queries++;
            if (as.isRegistryExpired()) {
                // Registro desatualizado.
                // Atualizando campos do registro.
                as.refresh();
            } else if (as.isRegistryAlmostExpired()) {
                // Registro quase vencendo.
                // Adicionar no conjunto para atualização em background.
                REFRESH.add(as);
            }
            return as;
        } else {
            // Realizando a consulta no WHOIS.
            AutonomousSystem as = new AutonomousSystem(number, server);
            // Adicinando registro em cache.
            MAP.put(as.getNumber(), as);
            AS_CHANGED = true;
            return as;
        }
    }
    
    /**
     * Conjunto de registros para atualização em background.
     */
    private static final TreeSet<AutonomousSystem> REFRESH = new TreeSet<AutonomousSystem>();
    
    /**
     * Atualiza em background todos os registros adicionados no conjunto.
     */
    public static synchronized void backgroundRefresh() {
        while (!REFRESH.isEmpty()) {
            AutonomousSystem as = REFRESH.pollFirst();
            try {
                // Atualizando campos do registro.
                as.refresh();
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    /**
     * Retorna o número do AS.
     * @return o número do AS.
     */
    public String getNumber() {
        return aut_num;
    }
    
    @Override
    public int hashCode() {
        return aut_num.hashCode();
    }
    
    @Override
    public boolean equals(Object other) {
        if (other instanceof Domain) {
            return equals((AutonomousSystem) other);
        } else {
            return false;
        }
    }
    
    /**
     * Verifica se o registro atual é o mesmo de outro.
     * @param other o outro registro a ser comparado.
     * @return verdadeiro se o registro passado é igual ao atual.
     */
    public boolean equals(AutonomousSystem other) {
        if (other == null) {
            return false;
        } else {
            return this.aut_num.equals(other.aut_num);
        }
    }
    
    @Override
    public int compareTo(AutonomousSystem other) {
        return this.aut_num.compareTo(other.aut_num);
    }
    
    @Override
    public String toString() {
        return aut_num;
    }
}
