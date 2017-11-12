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
 * Representa uma distribuição normal com população fixa de 32.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class NormalDistribution implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private float xiSum;
    private float xi2Sum;
    
    private static final int POPULATION = 32;
    
    public void add(NormalDistribution other) {
        if (other != null) {
            this.xiSum = 1.0f / ((1.0f / this.xiSum) + (1.0f / other.xiSum));
            this.xi2Sum = 1.0f / ((1.0f / this.xi2Sum) + (1.0f / other.xi2Sum));
        }
    }
    
    /**
     * Inicia uma distribuição normal com população cheia com média zero.
     */
    public NormalDistribution() {
        xiSum = 0.0f;
        xi2Sum = 0.0f;
    }
    
    private NormalDistribution(float xiSum, float xi2Sum) {
        this.xiSum = xiSum;
        this.xi2Sum = xi2Sum;
    }
    
    public static NormalDistribution newDistribution(
            String xiSum,
            String xi2Sum
    ) {
        if (xiSum == null || xiSum.length() == 0) {
            return null;
        } else if (xi2Sum == null || xi2Sum.length() == 0) {
            return null;
        } else {
            try {
                float xiSumLocal = Float.parseFloat(xiSum);
                float xi2SumLocal = Float.parseFloat(xi2Sum);
                return new NormalDistribution(xiSumLocal, xi2SumLocal);
            } catch (NumberFormatException ex) {
                return null;
            }
        }
    }
    
    public NormalDistribution replicate() {
        NormalDistribution clone = new NormalDistribution();
        clone.xiSum = this.xiSum;
        clone.xi2Sum = this.xi2Sum;
        return clone;
    }
    
    /**
     * Inicia uma distribuição normal com população cheia com média definida.
     * @param avg a média da população.
     */
    public NormalDistribution(float avg) {
        // Adiciona a população completa pela média.
        xiSum = avg * POPULATION;
        xi2Sum = avg * avg * POPULATION;
    }
    
    public synchronized void addElement(float value) {
        // Retira um elemento médio da população.
        xiSum -= xiSum / POPULATION;
        xi2Sum -= xi2Sum / POPULATION;
        // Adiciona o novo elemento na população.
        xiSum += value;
        xi2Sum += value * value;
    }
    
    public synchronized Float[] getXiSum() {
        Float[] xiResult = new Float[2];
        xiResult[0] = xiSum;
        xiResult[1] = xi2Sum;
        return xiResult;
    }
    
    public float getAverage() {
        return xiSum / POPULATION;
    }
    
    public double getMinimum() {
        return getAverage() - getStandardError();
    }
    
    public int getMinimumInt() {
        return (int) getMinimum();
    }
    
    public double getMaximum() {
        return getAverage() + getStandardError();
    }
    
    public int getMaximumInt() {
        return (int) getMaximum();
    }
    
    public double getStandardDeviation() {
        float avg = xiSum / POPULATION;
        float std = xi2Sum;
        std -= 2 * avg * xiSum;
        std += POPULATION * avg * avg;
        std /= POPULATION - 1;
        return Math.sqrt(std);
    }
    
    public double getStandardError() {
        return getStandardDeviation() / Math.sqrt(POPULATION);
    }
    
    public String toStringInt() {
        int average = Math.round(getAverage());
        int stdError = (int) getStandardError();
        if (stdError == 0) {
            return Integer.toString(average);
        } else {
            return average + "±" + stdError;
        }
    }
    
    @Override
    public String toString() {
        return Core.DECIMAL_FORMAT.format(getAverage()) +
                "±" + Core.DECIMAL_FORMAT.format(getStandardError());
    }
}
