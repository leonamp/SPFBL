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
package br.com.allchemistry.whois;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;

/**
 * Representa o registro de dono de um resultado WHOIS.
 * 
 * A chave primária dos registros é o atributo ownerid.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Owner implements Serializable, Comparable<Owner> {
    
    private static final long serialVersionUID = 1L;
    
    public String owner; // Nome do dono.
    public String ownerid; // Identificação do dono.
    public String responsible; // Responsável pelo registro.
    public String country; // País onde o dono foi registrado.
    public String owner_c; // Código do dono.
    public Date created; // Data de criação do registro.
    public Date changed; // Data da alteração do registro.
    public String provider; // Provedor de responsável.
    
    /**
     * Lista dos dominios registrados.
     */
    public final ArrayList<String> domainList = new ArrayList<String>();
    
    public String server = null; // Servidor onde a informação do registro pode ser encontrada.
    public long lastRefresh = 0; // Última vez que houve atualização do registro em milisegundos.
    public boolean reduced = false; // Diz se a última consulta foi reduzida.
    public int queries = 1; // Contador de consultas.
    
    @Override
    public int compareTo(Owner other) {
        return this.owner.compareTo(other.owner);
    }
}
