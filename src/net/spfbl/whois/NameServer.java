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
import java.util.HashMap;
import java.util.TreeSet;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Representa o registro de servidor de nome.
 * 
 * A chave primária do registro é o atributo nserver.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class NameServer implements Serializable, Comparable<NameServer> {
    
    private static final long serialVersionUID = 1L;
    
    private final String nserver; // Hostname do servidor de nome.
    private String nsstat;
    private String nslastaa;
    
    private long lastQuery = 0; // Última vez que houve atualização do registro em milisegundos.
    
    private static final int REFRESH_TIME = 84; // Prazo máximo que o registro deve permanecer em cache em dias.
    
    /**
     * Inicia um registro vazio.
     * @param nserver o host do registro.
     */
    private NameServer(String nserver) {
        this.nserver = nserver;
        this.lastQuery = System.currentTimeMillis();
        // Atualiza flag de atualização.
        NS_CHANGED = true;
    }
    
    public boolean isRegistryExpired() {
        long expiredTime = (System.currentTimeMillis() - lastQuery) / Server.DAY_TIME;
        return expiredTime > REFRESH_TIME;
    }
    
    /**
     * Altera o nsstat do registro.
     * @param nsstat o novo nsstat do registro.
     * @throws ProcessException se houver falha no processamento.
     */
    public void setStat(String nsstat) throws ProcessException {
        if (nsstat == null) {
            throw new ProcessException("ERROR: INVALID STAT");
        } else if (!nsstat.equals(this.nsstat)) {
            this.nsstat = nsstat;
            this.lastQuery = System.currentTimeMillis();
            // Atualiza flag de atualização.
            NS_CHANGED = true;
        }
    }
    
    /**
     * Altera o nslastaa do registro.
     * @param nslastaa o novo nslastaa do registro.
     * @throws ProcessException se houver falha no processamento.
     */
    public void setLastAA(String nslastaa) throws ProcessException {
        if (nslastaa == null) {
            throw new ProcessException("ERROR: INVALID LASTAA");
        } else if (!nslastaa.equals(this.nslastaa)) {
            this.nslastaa = nslastaa;
            this.lastQuery = System.currentTimeMillis();
            // Atualiza flag de atualização.
            NS_CHANGED = true;
        }
    }
    
    /**
     * Retorna o valor de um campo do registro ou o valor de uma função.
     * @param key o campo do registro cujo valor deve ser retornado.
     * @return o valor de um campo do registro ou o valor de uma função.
     */
    public String get(String key) {
        lastQuery = System.currentTimeMillis();
        if (key.equals("nserver")) {
            return nserver;
        } else if (key.equals("nsstat")) {
            return nsstat;
        } else if (key.equals("nslastaa")) {
            return nslastaa;
        } else {
            return null;
        }
    }
    
    /**
     * Mapa de registros com busca de hash O(1).
     */
    private static final HashMap<String,NameServer> NS_MAP = new HashMap<>();
    
    protected synchronized boolean drop() {
        if (NS_MAP.remove(nserver) != null) {
            NS_CHANGED = true;
            return true;
        } else {
            return false;
        }
    }
    
    private static synchronized NameServer getMap(String nserver) {
        return NS_MAP.get(nserver);
    }
    
    private static synchronized NameServer putMap(String nserver, NameServer ns) {
        return NS_MAP.put(nserver, ns);
    }
    
    private static synchronized TreeSet<String> getKeySet() {
        TreeSet<String> keySet = new TreeSet<>();
        keySet.addAll(NS_MAP.keySet());
        return keySet;
    }
    
    private static HashMap<String,NameServer> getMap() {
        HashMap<String,NameServer> map = new HashMap<>();
        for (String key : getKeySet()) {
            NameServer ns = getMap(key);
            if (ns != null) {
                if (ns.isRegistryExpired()) {
                    ns.drop();
                } else {
                    map.put(key, ns);
                }
            }
        }
        return map;
    }
    
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean NS_CHANGED = false;
    
    /**
     * Retorna o servidor de nome de código informado.
     * @param nserver o código do servidor de nome.
     * @return o servidor de nome de código informado.
     */
    public static NameServer getNameServer(String nserver) {
        nserver = nserver.trim(); // Implementar validação.
        NameServer ns = getMap(nserver);
        if (ns == null) {
            ns = new NameServer(nserver);
            putMap(nserver, ns);
        }
        return ns;
    }
    
    /**
     * Armazenamento de cache em disco.
     */
    public static void store() {
        if (NS_CHANGED) {
            try {
                long time = System.currentTimeMillis();
                HashMap<String,NameServer> map = getMap();
                File file = new File("./data/ns.map");
                try (FileOutputStream outputStream = new FileOutputStream(file)) {
                    SerializationUtils.serialize(map, outputStream);
                    // Atualiza flag de atualização.
                    NS_CHANGED = false;
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
    public static void load() {
        long time = System.currentTimeMillis();
        File file = new File("./data/ns.map");
        if (file.exists()) {
            try {
                HashMap<String,NameServer> map;
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    map = SerializationUtils.deserialize(fileInputStream);
                }
                for (String key : map.keySet()) {
                    Object value = map.get(key);
                    if (value instanceof NameServer) {
                        NameServer ns = (NameServer) value;
                        putMap(key, ns);
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
        return nserver.hashCode();
    }
    
    @Override
    public boolean equals(Object other) {
        if (other instanceof NameServer) {
            return equals((NameServer) other);
        } else {
            return false;
        }
    }
    
    public boolean equals(NameServer other) {
        if (other == null) {
            return false;
        } else {
            return this.nserver.equals(other.nserver);
        }
    }
    
    @Override
    public int compareTo(NameServer other) {
        return this.nserver.compareTo(other.nserver);
    }
    
    @Override
    public String toString() {
        return nserver;
    }
}
