package net.spfbl.core;

import java.io.FileWriter;
import java.io.IOException;
import java.util.StringTokenizer;

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
 * along with SPFBL. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * Class to measure a time period in milliseconds.
 * 
 * Max period is a week.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Period {
    
    private short population;
    private int xSum;
    private long x2Sum;
    private long last;
    
    protected Period(short population, int xSum, long x2Sum, long last) {
        this.population = population;
        this.xSum = xSum;
        this.x2Sum = x2Sum;
        this.last = last;
    }
    
    public Period() {
        this.population = 0;
        this.xSum = 0;
        this.x2Sum = 0;
        this.last = 0L;
    }
    
    public String storeLine() {
        Number[] values = getValues();
        return values[0] + " " + values[1] + " " + values[2] + " " + values[3];
    }
    
    public static Period loadLine(String line) {
        if (line == null) {
            return null;
        } else {
            StringTokenizer tokenizer = new StringTokenizer(line, " ");
            if (tokenizer.countTokens() == 4) {
                try {
                    short population = Short.parseShort(tokenizer.nextToken());
                    int xSum = Integer.parseInt(tokenizer.nextToken());
                    long x2Sum = Long.parseLong(tokenizer.nextToken());
                    long last = Long.parseLong(tokenizer.nextToken());
                    if (population < 0) {
                        return null;
                    } else if (xSum < 0) {
                        return null;
                    } else if (x2Sum < 0) {
                        return null;
                    } else if (last < 0) {
                        return null;
                    } else {
                        return new Period(population, xSum, x2Sum, last);
                    }
                } catch (NumberFormatException ex) {
                    return null;
                }
            } else {
                return null;
            }
        }
    }
    
    public synchronized void registerEvent() {
        long current = System.currentTimeMillis();
        if (last > 0) {
            // Calculate next interval.
            long interval = current - last;
            // Add new element.
            addInterval(interval);
        }
        last = current;
    }
    
    private static final long WEEK = 604800000L;
    
    private synchronized void addInterval(long interval) {
        if (interval < 0 || interval > WEEK) {
            population = 0;
            xSum = 0;
            x2Sum = 0;
        } else if (xSum + interval > WEEK) {
            int alive = (int) (population * Math.abs(WEEK - interval) / xSum);
            if (alive == 0) {
                population = 1;
                xSum = (int) interval;
                x2Sum = interval * interval;
            } else {
                int dead = population - alive;
                xSum -= dead * (xSum / population);
                x2Sum -= dead * (x2Sum / population);
                population = (short) (alive + 1);
                xSum += interval;
                x2Sum += interval * interval;
            }
        } else if (population == Short.MAX_VALUE) {
            xSum -= xSum / population;
            x2Sum -= x2Sum / population;
            xSum += interval;
            x2Sum += interval * interval;
        } else {
            population++;
            xSum += interval;
            x2Sum += interval * interval;
        }
    }
    
    public synchronized long getLast() {
        return last;
    }
    
    public synchronized short getPopulation() {
        return population;
    }
    
    private synchronized Number[] getValues() {
        Number[] fundamental = new Number[4];
        fundamental[0] = population;
        fundamental[1] = xSum;
        fundamental[2] = x2Sum;
        fundamental[3] = last;
        return fundamental;
    }
    
    private synchronized Number[] getFundamentalValues() {
        Number[] fundamental = new Number[3];
        fundamental[0] = population;
        fundamental[1] = xSum;
        fundamental[2] = x2Sum;
        return fundamental;
    }
    
    private Number[] getStatisticalValues() {
        Number[] fundamental = getFundamentalValues();
        short populationLocal = (short) fundamental[0];
        Number[] statistical = new Number[3];
        if (populationLocal == 0) {
            statistical[0] = Float.POSITIVE_INFINITY;
            statistical[1] = Double.POSITIVE_INFINITY;
            statistical[2] = Double.POSITIVE_INFINITY;
        } else if (populationLocal == 1) {
            int interval = (Integer) fundamental[1];
            statistical[0] = (float) interval;
            statistical[1] = (double) interval;
            statistical[2] = (double) interval;
        } else {
            int xSumLocal = (Integer) fundamental[1];
            long x2SumLocal = (Long) fundamental[2];
            float avg = (float) xSumLocal / populationLocal;
            double std = (double) x2SumLocal;
            std -= 2.0d * (double) avg * (double) xSumLocal;
            std += populationLocal * avg * avg;
            std /= populationLocal - 1;
            std = Math.sqrt(std);
            double stdError = std / Math.sqrt(populationLocal);
            statistical[0] = avg;
            statistical[1] = std;
            statistical[2] = stdError;
        }
        return statistical;
    }
    
    public float getAverage() {
        return (float) getStatisticalValues()[0];
    }
    
    public double getStandardDeviation() {
        return (double) getStatisticalValues()[1];
    }
    
    public double getStandardError() {
        return (double) getStatisticalValues()[2];
    }
    
    public boolean isExpired() {
        return System.currentTimeMillis() - getLast() > WEEK;
    }
    
    public boolean isExpired(int expiration) {
        return System.currentTimeMillis() - getLast() > expiration;
    }
    
    public boolean isAbusing(int minPop, int maxPop, int expiration, long time) {
        int pop = getPopulation();
        if (pop < minPop) {
            return false;
        } else if (isExpired(expiration)) {
            return false;
        } else if (pop > maxPop) {
            return true;
        } else {
            Number[] statistical = getStatisticalValues();
            float avg = (float) statistical[0];
            double stdError = (double) statistical[2];
            return avg + stdError < time;
        }
    }
    
    public boolean isAbusing(int minPop, int expiration, long time) {
        if (getPopulation() < minPop) {
            return false;
        } else if (isExpired(expiration)) {
            return false;
        } else {
            Number[] statistical = getStatisticalValues();
            float avg = (float) statistical[0];
            double stdError = (double) statistical[2];
            return avg + stdError < time;
        }
    }
    
    public boolean isAbusing(int minPop, long time) {
        if (getPopulation() < minPop) {
            return false;
        } else {
            Number[] statistical = getStatisticalValues();
            float avg = (float) statistical[0];
            double stdError = (double) statistical[2];
            return avg + stdError < time;
        }
    }
    
    private static final float SECOND = 1000.0f;
    private static final float MINUTE = SECOND * 60;
    private static final float HOUR = MINUTE * 60;
    private static final float DAY = HOUR * 24;
    
    @Override
    public String toString() {
        Number[] statistical = getStatisticalValues();
        float avg = (float) statistical[0];
        if (avg == Float.POSITIVE_INFINITY) {
            return "∞";
        } else {
            double stdError = (double) statistical[2];
            int avgInt;
            int stdErrorInt;
            String scale;
            if (avg >= DAY) {
                avgInt = (int) (avg / DAY);
                stdErrorInt = (int) (stdError / DAY);
                scale = "d";
            } else if (avg >= HOUR) {
                avgInt = (int) (avg / HOUR);
                stdErrorInt = (int) (stdError / HOUR);
                scale = "h";
            } else if (avg >= MINUTE) {
                avgInt = (int) (avg / MINUTE);
                stdErrorInt = (int) (stdError / MINUTE);
                scale = "min";
            } else if (avg >= SECOND) {
                avgInt = (int) (avg / SECOND);
                stdErrorInt = (int) (stdError / SECOND);
                scale = "s";
            } else {
                avgInt = (int) avg;
                stdErrorInt = (int) stdError;
                scale = "ms";
            }
            if (stdErrorInt == 0) {
                return avgInt + scale;
            } else {
                return avgInt + "±" + stdErrorInt + scale;
            }
        }
    }
}
