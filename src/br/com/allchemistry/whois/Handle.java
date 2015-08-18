/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.com.allchemistry.whois;

import br.com.allchemistry.core.Server;
import br.com.allchemistry.core.ProcessException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.Serializable;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Representa um registro de um contato.
 * 
 * A chave primária do registro é o atributo nic_hdl_br.
 * 
 * @author Leandro Carlos Rodrigues <leandro@allchemistry.com.br>
 */
public class Handle implements Serializable, Comparable<Handle> {
    
    private static final long serialVersionUID = 1L;
    
    private final String nic_hdl_br; // Código do registro.
    private String person; // Nome da pessoa.
    private String e_mail; // E-mail da pessoa.
    private Date created; // Data de criação do registro.
    private Date changed = null; // Data de alteração do registro.
    
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
        // Atualiza flag de atualização.
        HANDLE_CHANGED = true;
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
            // Atualiza flag de atualização.
            HANDLE_CHANGED = true;
        }
    }
    
    /**
     * Altera o e-mail da pessoa.
     * @param e_mail o novo e-mail da pessoa.
     * @throws ProcessException se houver falha no processamento.
     */
    public void setEmail(String e_mail) throws ProcessException {
        if (e_mail == null) {
            if (this.e_mail != null) {
                this.e_mail = e_mail;
                // Atualiza flag de atualização.
                HANDLE_CHANGED = true;
            }
        } else if (!e_mail.equals(this.e_mail)) {
            this.e_mail = e_mail;
            // Atualiza flag de atualização.
            HANDLE_CHANGED = true;
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
        } else {
            try {
                Date createdDate = DATE_FORMATTER.parse(created);
                if (!createdDate.equals(this.created)) {
                    this.created = createdDate;
                    // Atualiza flag de atualização.
                    HANDLE_CHANGED = true;
                }
            } catch (ParseException ex) {
                Server.logError(ex);
                throw new ProcessException("ERROR: PARSING CREATED " + created);
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
                // Atualiza flag de atualização.
                HANDLE_CHANGED = true;
            }
        } else {
            try {
                Date changedDate = DATE_FORMATTER.parse(changed);
                if (!changedDate.equals(this.changed)) {
                    this.changed = changedDate;
                    // Atualiza flag de atualização.
                    HANDLE_CHANGED = true;
                }
            } catch (ParseException ex) {
                Server.logError(ex);
                throw new ProcessException("ERROR: PARSING CHANGED " + changed);
            }
        }
    }
    
    /**
     * Retorna o valor de um campo do registro ou o valor de uma função.
     * @param key o campo do registro cujo valor deve ser retornado.
     * @return o valor de um campo do registro ou o valor de uma função.
     */
    public String get(String key) throws ProcessException {
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
            return DATE_FORMATTER.format(created);
        } else if (key.equals("changed")) {
            return DATE_FORMATTER.format(changed);
        } else {
            return null;
        }
    }
    
    /**
     * Mapa de registros com busca de hash O(1).
     */
    private static final HashMap<String,Handle> HANDLE_MAP = new HashMap<String,Handle>();
    
    /**
     * Flag que indica se o cache em disco foi modificado.
     */
    private static boolean HANDLE_CHANGED = false;
    
    /**
     * Retorna a pessoa de código informado.
     * @param nichdlbr o código da pessoa.
     * @return a pessoa de código informado.
     */
    public static synchronized Handle getHandle(String nichdlbr) {
        nichdlbr = nichdlbr.trim(); // Implementar validação.
        if (HANDLE_MAP.containsKey(nichdlbr)) {
            return HANDLE_MAP.get(nichdlbr);
        } else {
            Handle ns = new Handle(nichdlbr);
            HANDLE_MAP.put(nichdlbr, ns);
            return ns;
        }
    }
    
    /**
     * Armazenamento de cache em disco.
     */
    public static synchronized void store() {
        if (HANDLE_CHANGED) {
            try {
                long time = System.currentTimeMillis();
                File file = new File("handle.map");
                FileOutputStream outputStream = new FileOutputStream(file);
                try {
                    SerializationUtils.serialize(HANDLE_MAP, outputStream);
                    // Atualiza flag de atualização.
                    HANDLE_CHANGED = false;
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
        File file = new File("handle.map");
        if (file.exists()) {
            try {
                HashMap<String, Handle> map;
                FileInputStream fileInputStream = new FileInputStream(file);
                try {
                    map = SerializationUtils.deserialize(fileInputStream);
                } finally {
                    fileInputStream.close();
                }
                HANDLE_MAP.putAll(map);
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
