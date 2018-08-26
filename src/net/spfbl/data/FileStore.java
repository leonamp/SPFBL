package net.spfbl.data;

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


import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.LinkedList;
import java.util.concurrent.Semaphore;
import net.spfbl.core.Server;

/**
 * Class for dynamic data storing system.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class FileStore extends Thread {
    
    private final File FILE;
    private FileWriter WRITER = null;
    private final LinkedList<String> LIST = new LinkedList<>();
    private final Semaphore SEMAPHORE = new Semaphore(1);
    private boolean keepRunning = true;
    
    public FileStore(File file) throws IOException {
        FILE = file;
        WRITER = new FileWriter(file, true);
        setPriority(Thread.MIN_PRIORITY);
    }
    
    @Override
    public void run() {
        try {
            while (keepRunning()) {
                whiteAll();
                waitNext();
            }
        } catch (Exception ex) {
            Server.logError(ex);
        }
    }
    
    private synchronized void whiteAll() throws IOException {
        if (WRITER != null) {
            String line;
            while ((line = LIST.poll()) != null) {
                WRITER.write(line + "\n");
            }
            WRITER.flush();
        }
    }
    
    private synchronized boolean keepRunning() throws InterruptedException {
        SEMAPHORE.acquire();
        return keepRunning;
    }
    
    private synchronized void waitNext() throws InterruptedException {
        SEMAPHORE.release();
        wait(60000);
    }
    
    public synchronized void append(String line) {
        LIST.offer(line);
        notify();
    }
    
    public synchronized File pause() throws IOException {
        try {
            SEMAPHORE.acquire();
            WRITER.close();
            WRITER = null;
            return FILE;
        } catch (InterruptedException ex) {
            Server.logError(ex);
            return FILE;
        } finally {
            SEMAPHORE.release();
        }
    }
    
    public synchronized void unpause() throws IOException {
        try {
            SEMAPHORE.acquire();
            WRITER = new FileWriter(FILE, true);
        } catch (InterruptedException ex) {
            Server.logError(ex);
        } finally {
            SEMAPHORE.release();
        }
    }
    
    public synchronized void close() throws IOException {
        try {
            SEMAPHORE.acquire();
            keepRunning = false;
            String line;
            while ((line = LIST.poll()) != null) {
                WRITER.write(line);
                WRITER.write("\n");
            }
            WRITER.close();
        } catch (InterruptedException ex) {
            Server.logError(ex);
        } finally {
            SEMAPHORE.release();
        }
    }
}
