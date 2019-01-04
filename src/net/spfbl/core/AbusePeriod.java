package net.spfbl.core;

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
 * Class to measure a abuse period in milliseconds.
 * 
 * Max period is a week.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class AbusePeriod extends Period {
    
    private long banned = 0;
    
    private AbusePeriod(
            short population, int xSum,
            long x2Sum, long last,
            long banned
    ) {
        super(population, xSum, x2Sum, last);
        this.banned = banned;
    }
    
    public AbusePeriod() {
        super();
        this.banned = 0L;
    }
    
    public synchronized void setBannedTime(long time) {
        this.banned = time;
    }
    
    public void setBannedInterval(long interval) {
        setBannedTime(System.currentTimeMillis() + interval);
    }
    
    public synchronized long getBannedTime() {
        return banned;
    }
    
    public boolean isBanned() {
        return System.currentTimeMillis() < getBannedTime();
    }
    
    @Override
    public String storeLine() {
        return super.storeLine() + " " + getBannedTime();
    }
    
    public static AbusePeriod loadLine(String line) {
        if (line == null) {
            return null;
        } else {
            StringTokenizer tokenizer = new StringTokenizer(line, " ");
            if (tokenizer.countTokens() == 5) {
                try {
                    short population = Short.parseShort(tokenizer.nextToken());
                    int xSum = Integer.parseInt(tokenizer.nextToken());
                    long x2Sum = Long.parseLong(tokenizer.nextToken());
                    long last = Long.parseLong(tokenizer.nextToken());
                    long banned = Long.parseLong(tokenizer.nextToken());
                    if (population < 0) {
                        return null;
                    } else if (xSum < 0) {
                        return null;
                    } else if (x2Sum < 0) {
                        return null;
                    } else if (last < 0) {
                        return null;
                    } else if (banned < 0) {
                        return null;
                    } else {
                        return new AbusePeriod(population, xSum, x2Sum, last, banned);
                    }
                } catch (NumberFormatException ex) {
                    return null;
                }
            } else {
                return null;
            }
        }
    }
}
