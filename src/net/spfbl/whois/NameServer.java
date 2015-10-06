/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package net.spfbl.whois;

import net.spfbl.core.Server;
import net.spfbl.core.ProcessException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.Serializable;
import java.util.HashMap;
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
    
    /**
     * Inicia um registro vazio.
     * @param nserver o host do registro.
     */
    private NameServer(String nserver) {
        this.nserver = nserver;
        // Atualiza flag de atualização.
        NS_CHANGED = true;
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
    private static final HashMap<String,NameServer> NS_MAP = new HashMap<String,NameServer>();
    
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
        if (NS_MAP.containsKey(nserver)) {
            return NS_MAP.get(nserver);
        } else {
            NameServer ns = new NameServer(nserver);
            NS_MAP.put(nserver, ns);
            return ns;
        }
    }
    
    /**
     * Armazenamento de cache em disco.
     */
    public static synchronized void store() {
        if (NS_CHANGED) {
            try {
                long time = System.currentTimeMillis();
                File file = new File("./data/ns.map");
                FileOutputStream outputStream = new FileOutputStream(file);
                try {
                    SerializationUtils.serialize(NS_MAP, outputStream);
                    // Atualiza flag de atualização.
                    NS_CHANGED = false;
                } finally {
                    outputStream.close();
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
    public static synchronized void load() {
        long time = System.currentTimeMillis();
        File file = new File("./data/ns.map");
        if (file.exists()) {
            try {
                HashMap<String, NameServer> map;
                FileInputStream fileInputStream = new FileInputStream(file);
                try {
                    map = SerializationUtils.deserialize(fileInputStream);
                } finally {
                    fileInputStream.close();
                }
                NS_MAP.putAll(map);
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
