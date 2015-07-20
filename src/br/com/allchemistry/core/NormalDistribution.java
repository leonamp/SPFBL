/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.com.allchemistry.core;

import java.io.Serializable;

/**
 * Representa uma distribuição normal com população fixa de 32.
 * 
 * @author Leandro Carlos Rodrigues <leandro@allchemistry.com.br>
 */
public class NormalDistribution implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private float xiSum;
    private float xi2Sum;
    
    private static final int POPULATION = 32;
    
    public static void main(String[] args) {
        NormalDistribution distribution = new NormalDistribution();
        for (int i = 0; i < 10000; i++) {
            distribution.addElement((float) Math.random());
            System.out.println(distribution);
        }
        
        for (int i = 0; i < 10000; i++) {
            distribution.addElement((float) Math.random() * 2);
            System.out.println(distribution);
        }
    }
    
    public NormalDistribution() {
        xiSum = 0.0f;
        xi2Sum = 0.0f;
    }
    
    public NormalDistribution(float value) {
        xiSum = value;
        xi2Sum = value * value;
    }
    
    public synchronized void addElement(float value) {
        xiSum -= xiSum / POPULATION;
        xi2Sum -= xi2Sum / POPULATION;
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
