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
package net.spfbl.core;

import java.io.Serializable;

/**
 * Representa um semáforo para alteração de um único valor binario.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class BinarySemaphore implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private Boolean state = false;
    
    public BinarySemaphore() {
        state = false;
    }
    
    public BinarySemaphore(boolean init) {
        state = init;
    }
        
    private synchronized boolean clearState() {
        if (state == null) {
            return false;
        } else {
            state = null;
            return true;
        }
    }
    
    private synchronized boolean clearState(boolean condition) {
        if (state == null) {
            return false;
        } else if (state == condition) {
            state = null;
            return true;
        } else {
            return false;
        }
    }

    private synchronized boolean setState(boolean value) {
        if (state == null) {
            state = value;
            return true;
        } else {
            return false;
        }
    }

    /**
     * Finaliza a alteração do valor após marcar o ponto inicial.
     * 
     * @param value o novo valor do estado.
     */
    public synchronized void release(boolean value) {
        if (setState(value)) {
            notify();
        }
    }

    /**
     * Marca um ponto de início de alteração de valor.
     */
    public synchronized void acquire() {
        while (!clearState()) {
            try {
                wait();
            } catch (InterruptedException ex) {
                Server.logError(ex);
            }
        }
    }
    
    /**
     * Tenta marcar um ponto de início de alteração 
     * se a condição for fatisfeita.
     * 
     * @param condition condição para marcar o 
     * ponto de inicio da alteração.
     * 
     * @return verdadeiro se o ponto for marcado com sucesso.
     */
    public boolean acquireIf(boolean condition) {
        return clearState(condition);
    }
}
