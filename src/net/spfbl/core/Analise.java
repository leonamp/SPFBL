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

import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import net.spfbl.data.Block;
import net.spfbl.data.Ignore;
import net.spfbl.spf.SPF;
import net.spfbl.spf.SPF.Distribution;
import net.spfbl.spf.SPF.Status;
import net.spfbl.whois.Domain;
import net.spfbl.whois.Subnet;

/**
 * Análise de listas de IP.
 *
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Analise implements Comparable<Analise> {

    private final String name; // Nome do processo.
    private final TreeSet<String> ipSet = new TreeSet<String>(); // Lista dos IPs a serem analisados.
    private final TreeSet<String> processSet = new TreeSet<String>(); // Lista dos IPs em processamento.
    private final TreeMap<String,String> resultMap = new TreeMap<String,String>(); // Lista dos resultados das anaises.
    
    private Analise(String name) {
        this.name = name;
    }
    
    public synchronized boolean add(String ip) {
        if (!Subnet.isValidIP(ip)) {
            return false;
        } else if (ipSet.contains(ip = Subnet.normalizeIP(ip))) {
            return false;
        } else if (processSet.contains(ip)) {
            return false;
        } else if (resultMap.containsKey(ip)) {
            return false;
        } else {
            ipSet.add(ip);
            if (SEMAPHORE.tryAcquire()) {
                Process process = new Process();
                process.start();
            }
            return true;
        }
    }
    
    public synchronized TreeSet<String> getResultSet() {
        TreeSet<String> set = new TreeSet<String>();
        for (String ip: ipSet) {
            set.add(ip + " WAITING");
        }
        for (String ip: processSet) {
            set.add(ip + " PROCESSING");
        }
        for (String ip : resultMap.keySet()) {
            String result = resultMap.get(ip);
            set.add(ip + " " + result);
        }
        return set;
    }
    
    public static void dumpAll(StringBuilder builder) {
        for (Analise analise : getAnaliseSet()) {
            analise.dump(builder);
        }
    }
    
    public void dump(StringBuilder builder) {
        for (String line : getResultSet()) {
            builder.append(line);
            builder.append('\n');
        }
    }
    
    private synchronized String pollFirst() {
        String ip = ipSet.pollFirst();
        if (ip == null) {
            return null;
        } else {
            processSet.add(ip);
            return ip;
        }
    }
    
    private boolean isWait() {
        return !ipSet.isEmpty();
    }
    
    private synchronized boolean addResult(String ip, String result) {
        processSet.remove(ip);
        return resultMap.put(ip, result) == null;
    }
    
    private boolean process() {
        String ip = pollFirst();
        if (ip == null) {
            return false;
        } else {
            StringBuilder builder = new StringBuilder();
            Analise.process(ip, builder);
            String result = builder.toString();
            if (addResult(ip, result)) {
                Server.logTrace(ip + ' ' + result);
            }
            return true;
        }
    }
    
    
    @Override
    public boolean equals(Object o) {
        if (o instanceof Analise) {
            Analise other = (Analise) o;
            return this.name.equals(other.name);
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }
    
    @Override
    public int compareTo(Analise other) {
        return this.name.compareTo(other.name);
    }
    
    @Override
    public synchronized String toString() {
        return name + " "
                + ipSet.size() + " "
                + processSet.size() + " "
                + resultMap.size();
    }
    
    /**
     * Fila de processos.
     */
    private static final LinkedList<Analise> QUEUE = new LinkedList<Analise>();
    /**
     * Mapa de processos.
     */
    private static final HashMap<String,Analise> MAP = new HashMap<String,Analise>();
    
    public synchronized static TreeSet<Analise> getAnaliseSet() {
        TreeSet<Analise> queue = new TreeSet<Analise>();
        queue.addAll(QUEUE);
        return queue;
    }
    
    public synchronized static TreeSet<String> getNameSet() {
        TreeSet<String> queue = new TreeSet<String>();
        queue.addAll(MAP.keySet());
        return queue;
    }
    
    public synchronized static Analise get(String name, boolean first) {
        Analise analise = MAP.get(name);
        if (analise == null) {
            analise = new Analise(name);
            MAP.put(name, analise);
            if (first) {
                QUEUE.addFirst(analise);
            } else {
                QUEUE.addLast(analise);
            }
        }
        return analise;
    }
    
    public synchronized static Analise drop(String name) {
        Analise analise;
        if ((analise = MAP.remove(name)) != null) {
            QUEUE.remove(analise);
        }
        return analise;
    }
    
    private synchronized static Analise getNextWait() {
        // Rotaciona para distribuir os processos.
        Analise analise = QUEUE.poll();
        if (analise == null) {
            return null;
        } else {
            QUEUE.offer(analise);
            for (Analise analise2 : QUEUE) {
                if (analise2.isWait()) {
                    return analise2;
                }
            }
            return null;
        }
    }
    
    public static void processToday(String ip) {
        Date today = new Date();
        String name = Core.SQL_FORMAT.format(today);
        Analise analise = Analise.get(name, true);
        analise.add(ip);
    }     
    
    public static void process(
            String ip,
            StringBuilder builder
            ) {
        try {
            Distribution distribution1 = SPF.getDistribution(ip, true);
            float probability1 = distribution1.getSpamProbability(ip);
            Status status1;
            Status status3 = distribution1.getStatus(ip);
            if (Block.containsIP(ip)) {
                status1 = Status.BLOCK;
                status3 = Status.BLOCK;
            } else if (Ignore.contains(ip)) {
                status1 = Status.IGNORE;
            } else if (Core.isOpenSMTP(ip, 25, 30000)) {
                status1 = status3;
            } else {
                status1 = Status.CLOSED;
            }
            builder.append(status1);
            String token = ip;
            for (String reverse : Reverse.getValidSet(ip, true)) {
                reverse = Domain.normalizeHostname(reverse, true);
                Distribution distribution2 = SPF.getDistribution(reverse, true);
                float probability2 = distribution2.getSpamProbability(reverse);
                Status status2 = distribution2.getStatus(reverse);
                if (probability2 > probability1) {
                    probability1 = probability2;
                    distribution1 = distribution2;
                }
                if (probability2 >= probability1 || Subnet.isValidIP(token)) {
                    token = reverse;
                    status3 = status2 == Status.BLOCK ? Status.BLACK : status2;
                    if (Block.containsHost(reverse)) {
                        status3 = Status.BLOCK;
                    } else if (Block.containsREGEX(reverse)) {
                        status3 = Status.BLOCK;
                    } else if (Ignore.contains(reverse)) {
                        status3 = Status.IGNORE;
                    }
                }
            }
            builder.append(' ');
            builder.append(token);
            builder.append(' ');
            builder.append(status3);
            builder.append(' ');
            builder.append(Core.DECIMAL_FORMAT.format(distribution1.getSpamProbability(ip)));
            builder.append(' ');
            builder.append(distribution1.getFrequencyLiteral());
            builder.append(' ');
            if (Subnet.isValidIP(token)) {
                builder.append(Subnet.expandIP(token));
            } else {
                builder.append(Domain.revert(token));
            }
        } catch (ProcessException ex) {
            builder.append("ERROR");
            Server.logError(ex);
        }
    }

    private static final int MAX = 128;
    private static final Semaphore SEMAPHORE = new Semaphore(MAX);
    private static boolean run = true;
    
    public static void interrupt() {
        run = false;
        int count = MAX;
        while (count > 0) {
            try {
                SEMAPHORE.acquire();
                count--;
            } catch (InterruptedException ex) {
                Server.logError(ex);
            }
        }
    }

    private class Process extends Thread {
        private Process() {
            super("ANALISEPS");
            super.setPriority(MIN_PRIORITY);
        }
        @Override
        public void run() {
            try {
                Analise analise;
                while (run && (analise = getNextWait()) != null) {
                    analise.process();
                }
            } finally {
                SEMAPHORE.release();
            }
        }
    }
}
