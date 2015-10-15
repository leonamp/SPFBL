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
import java.util.Date;
import java.util.TreeSet;

/**
 *
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class AutonomousSystem implements Serializable, Comparable<AutonomousSystem>  {
    
    private static final long serialVersionUID = 1L;
    
    public String aut_num;
    public String owner;
    public String ownerid;
    public String responsible;
    public String country;
    public String owner_c;
    public String routing_c;
    public String abuse_c;
    public Date created;
    public Date changed;

    /**
     * Lista dos blocos alocados ao AS.
     */
    public final TreeSet<String> inetnumSet = new TreeSet<String>();
    
    public String server; // Servidor onde a informação do AS pode ser encontrada.
    public long lastRefresh = 0; // Última vez que houve atualização do registro em milisegundos.
    public boolean reduced = false; // Diz se a última consulta foi reduzida.
    public int queries = 1; // Contador de consultas.
    
    @Override
    public int compareTo(AutonomousSystem other) {
        return this.aut_num.compareTo(other.aut_num);
    }
    
    @Override
    public String toString() {
        return aut_num;
    }
}
