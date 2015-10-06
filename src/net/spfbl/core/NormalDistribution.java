/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
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
    
    public NormalDistribution(br.com.allchemistry.core.NormalDistribution other) {
        this.xiSum = other.xiSum;
        this.xi2Sum = other.xi2Sum;
    }
    
    /**
     * Inicia uma distribuição normal com população cheia com média zero.
     */
    public NormalDistribution() {
        xiSum = 0.0f;
        xi2Sum = 0.0f;
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
    
    public float getAverage() {
        return xiSum / POPULATION;
    }
    
    public double getMinimum() {
        return getAverage() - getStandardError();
    }
    
    public double getMaximum() {
        return getAverage() + getStandardError();
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
        return Server.DECIMAL_FORMAT.format(getAverage()) +
                "±" + Server.DECIMAL_FORMAT.format(getStandardError());
    }
}
