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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.Serializable;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.TreeSet;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Representa um registro de um contato.
 * 
 * A chave primária do registro é o atributo nic_hdl_br.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Handle implements Serializable, Comparable<Handle> {
    
    private static final long serialVersionUID = 1L;
    
    private final String nic_hdl_br; // Código do registro.
    private String person; // Nome da pessoa.
    private String e_mail; // E-mail da pessoa.
    private Date created; // Data de criação do registro.
    private Date changed = null; // Data de alteração do registro.
    private String provider = null;
    private String country = null;
    
    private long lastQuery = 0; // Última vez que houve atualização do registro em milisegundos.
    
    private static final int REFRESH_TIME = 84; // Prazo máximo que o registro deve permanecer em cache em dias.
    
    /**
     * Formatação padrão dos campos de data do WHOIS.
     */
    private static final SimpleDateFormat DATE_FORMATTER = new SimpleDateFormat("yyyyMMdd");
    
    /**
     * Inicia um registro vazio.
     * @param nic_hdl_br o código do registro.
     */
    private Handle(String nic_hdl_br) {
        this.nic_hdl_br = nic_hdl_br;
        this.lastQuery = System.currentTimeMillis();
        // Atualiza flag de atualização.
        CHANGED = true;
    }
    
    public boolean isRegistryExpired() {
        long expiredTime = (System.currentTimeMillis() - lastQuery) / Server.DAY_TIME;
        return expiredTime > REFRESH_TIME;
    }
    
    /**
     * Altera o nome da pessoa.
     * @param person o novo nome da pessoa.
     * @throws ProcessException se houver falha no processamento.
     */
    public void setPerson(String person) throws ProcessException {
        if (person == null) {
            throw new ProcessException("ERROR: INVALID PERSON");
        } else if (!person.equals(this.person)) {
            this.person = person;
            this.lastQuery = System.currentTimeMillis();
            // Atualiza flag de atualização.
            CHANGED = true;
        }
    }
    
    /**
     * Altera o e-mail da pessoa.
     * @param e_mail o novo e-mail da pessoa.
     * @throws ProcessException se houver falha no processamento.
     */
    public void setEmail(String e_mail) throws ProcessException {
        if (e_mail != null && !e_mail.equals(this.e_mail)) {
            this.e_mail = e_mail;
            this.lastQuery = System.currentTimeMillis();
            // Atualiza flag de atualização.
            CHANGED = true;
        }
    }
    
    /**
     * Altera a data de criação do registro.
     * @param created a nova data de criação do registro.
     * @throws ProcessException se houver falha no processamento.
     */
    public void setCreated(String created) throws ProcessException {
        if (created == null) {
            throw new ProcessException("ERROR: INVALID CREATED");
        } else if (created.length() < 8) {
            this.created = null;
            this.lastQuery = System.currentTimeMillis();
        } else {
            try {
                Date createdDate = DATE_FORMATTER.parse(created);
                if (!createdDate.equals(this.created)) {
                    this.created = createdDate;
                    this.lastQuery = System.currentTimeMillis();
                    // Atualiza flag de atualização.
                    CHANGED = true;
                }
            } catch (ParseException ex) {
                this.created = null;
                Server.logTrace(created);
                Server.logError(ex);
            }
        }
    }
    
    /**
     * Altera a data de allteração do registro.
     * @param changed a nova data de alteração do registro.
     * @throws ProcessException se houver falha no processamento.
     */
    public void setChanged(String changed) throws ProcessException {
        if (changed == null) {
            throw new ProcessException("ERROR: CREATED CHANGED");
        } else if (changed.length() == 0) {
            if (this.changed != null) {
                this.changed = null;
                this.lastQuery = System.currentTimeMillis();
                // Atualiza flag de atualização.
                CHANGED = true;
            }
        } else {
            try {
                Date changedDate = DATE_FORMATTER.parse(changed);
                if (!changedDate.equals(this.changed)) {
                    this.changed = changedDate;
                    this.lastQuery = System.currentTimeMillis();
                    // Atualiza flag de atualização.
                    CHANGED = true;
                }
            } catch (ParseException ex) {
                Server.logTrace(changed);
                Server.logError(ex);
            }
        }
    }
    
    /**
     * Altera o provedor da pessoa.
     * @param provider o novo provedor da pessoa.
     * @throws ProcessException se houver falha no processamento.
     */
    public void setProvider(String provider) throws ProcessException {
        if (provider == null) {
            if (this.provider != null) {
                this.provider = provider;
                this.lastQuery = System.currentTimeMillis();
                // Atualiza flag de atualização.
                CHANGED = true;
            }
        } else if (!provider.equals(this.provider)) {
            this.provider = provider;
            this.lastQuery = System.currentTimeMillis();
            // Atualiza flag de atualização.
            CHANGED = true;
        }
    }
    
    /**
     * Altera o pais da pessoa.
     * @param country o novo pais da pessoa.
     * @throws ProcessException se houver falha no processamento.
     */
    public void setCountry(String country) throws ProcessException {
        if (country == null) {
            if (this.country != null) {
                this.country = country;
                this.lastQuery = System.currentTimeMillis();
                // Atualiza flag de atualização.
                CHANGED = true;
            }
        } else if (!country.equals(this.country)) {
            this.country = country;
            this.lastQuery = System.currentTimeMillis();
            // Atualiza flag de atualização.
            CHANGED = true;
        }
    }
    
    private void setQuery() {
        this.lastQuery = System.currentTimeMillis();
    }
    
    /**
     * Retorna o valor de um campo do registro ou o valor de uma função.
     * @param key o campo do registro cujo valor deve ser retornado.
     * @return o valor de um campo do registro ou o valor de uma função.
     */
    public String getValue(String key) throws ProcessException {
        setQuery();
        if (key.equals("nic-hdl-br")) {
            return nic_hdl_br;
        } else if (key.equals("person")) {
            return person;
        } else if (key.equals("e-mail")) {
            if (e_mail == null) {
                throw new ProcessException("ERROR: WHOIS QUERY LIMIT");
            } else {
                return e_mail;
            }
        } else if (key.equals("created")) {
            if (created == null) {
                return null;
            } else {
                try {
                    return DATE_FORMATTER.format(created);
                } catch (Exception ex) {
                    Server.logError("Cannot format date: " + created);
                    return null;
                }
            }
        } else if (key.equals("changed")) {
            if (changed == null) {
                return null;
            } else {
                try {
                    return DATE_FORMATTER.format(changed);
                } catch (Exception ex) {
                    Server.logError("Cannot format date: " + changed);
                    return null;
                }
            }
        } else if (key.equals("provider")) {
            return provider;
        } else if (key.equals("country")) {
            return country;
        } else {
            return null;
        }
    }
    
    /**
     * Mapa de registros com busca de hash O(1).
     */
    private static final HashMap<String,Handle> MAP = new HashMap<>();
    
    /**
     * Flag que indica se o cache em disco foi modificado.
     */
    private static boolean CHANGED = false;
    
    protected synchronized boolean drop() {
        if (MAP.remove(nic_hdl_br) != null) {
            CHANGED = true;
            return true;
        } else {
            return false;
        }
    }
    
    /**
     * Retorna a pessoa de código informado.
     * @param nichdlbr o código da pessoa.
     * @return a pessoa de código informado.
     */
    public static synchronized Handle getHandle(String nichdlbr) {
        if (nichdlbr == null) {
            return null;
        } else if (MAP.containsKey(nichdlbr)) {
            Handle ns = MAP.get(nichdlbr);
            ns.setQuery();
            return ns;
        } else {
            Handle ns = new Handle(nichdlbr);
            MAP.put(nichdlbr, ns);
            return ns;
        }
    }
    
    private static synchronized TreeSet<String> getKeySet() {
        TreeSet<String> keySet = new TreeSet<>();
        keySet.addAll(MAP.keySet());
        return keySet;
    }
    
    private static synchronized Handle get(String key) {
        return MAP.get(key);
    }
    
    public static HashMap<String,Handle> getMap() {
        HashMap<String,Handle> map = new HashMap<>();
        for (String key : getKeySet()) {
            Handle handle = get(key);
            if (handle != null) {
                if (handle.isRegistryExpired()) {
                    handle.drop();
                } else {
                    map.put(key, handle);
                }
            }
        }
        return map;
    }
    
    /**
     * Armazenamento de cache em disco.
     */
    public static void store() {
        if (CHANGED) {
            try {
                long time = System.currentTimeMillis();
                HashMap<String,Handle> map = getMap();
                File file = new File("./data/handle.map");
                try (FileOutputStream outputStream = new FileOutputStream(file)) {
                    SerializationUtils.serialize(map, outputStream);
                    // Atualiza flag de atualização.
                    CHANGED = false;
                }
                Server.logStore(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private static synchronized Handle put(String key, Handle handle) {
        return MAP.put(key, handle);
    }
    
    /**
     * Carregamento de cache do disco.
     */
    public static void load() {
        long time = System.currentTimeMillis();
        File file = new File("./data/handle.map");
        if (file.exists()) {
            try {
                HashMap<String,Object> map;
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    map = SerializationUtils.deserialize(fileInputStream);
                }
                for (String key : map.keySet()) {
                    Object value = map.get(key);
                    if (value instanceof Handle) {
                        Handle handle = (Handle) value;
                        put(key, handle);
                    }
                }
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }

    @Override
    public int hashCode() {
        return nic_hdl_br.hashCode();
    }
    
    @Override
    public boolean equals(Object other) {
        if (other instanceof Handle) {
            return equals((Handle) other);
        } else {
            return false;
        }
    }
    
    public boolean equals(Handle other) {
        if (other == null) {
            return false;
        } else {
            return this.nic_hdl_br.equals(other.nic_hdl_br);
        }
    }
    
    @Override
    public int compareTo(Handle other) {
        return this.nic_hdl_br.compareTo(other.nic_hdl_br);
    }
    
    @Override
    public String toString() {
        return nic_hdl_br;
    }
}
