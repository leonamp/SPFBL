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
 * Representa uma distribuição binomial.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class BinomialDistribution implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private int failure;
    private int sucess;
    
    public void add(BinomialDistribution other) {
        if (other != null) {
            this.failure += other.failure;
            this.sucess += other.sucess;
        }
    }
    
    /**
     * Inicia uma distribuição normal com população cheia com média zero.
     */
    public BinomialDistribution() {
        failure = 0;
        sucess = 0;
    }
    
    private BinomialDistribution(int failure, int sucess) {
        this.failure = failure;
        this.sucess = sucess;
    }
    
    public static BinomialDistribution newDistribution(
            String failure,
            String sucess
    ) {
        if (failure == null || failure.length() == 0) {
            return null;
        } else if (sucess == null || sucess.length() == 0) {
            return null;
        } else {
            try {
                int failureLocal = Integer.parseInt(failure);
                int sucessLocal = Integer.parseInt(sucess);
                return new BinomialDistribution(failureLocal, sucessLocal);
            } catch (NumberFormatException ex) {
                return null;
            }
        }
    }
    
    public BinomialDistribution replicate() {
        BinomialDistribution clone = new BinomialDistribution();
        clone.failure = this.failure;
        clone.sucess = this.sucess;
        return clone;
    }
    
    public synchronized int getFailure() {
        return this.failure;
    }
    
    public synchronized int getSucess() {
        return this.sucess;
    }
    
    public synchronized void addFailure() {
        this.failure++;
    }
    
    public synchronized void addFailure(int count) {
        this.failure += count;
    }
    
    public synchronized void addSucess() {
        this.sucess++;
    }
    
    public synchronized void addSucess(int count) {
        this.sucess += count;
    }
    
    @Override
    public String toString() {
        int n = failure + sucess;
        if (n == 0) {
            return "UNDEFINED";
        } else {
            float p = (float) sucess / (float) n;
            return "B(" + n + "," + p + ")";
        }
    }
}
