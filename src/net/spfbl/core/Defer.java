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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.Serializable;
import java.util.HashMap;
import java.util.TreeSet;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Representa um registro de atraso de mensagem.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Defer implements Serializable, Comparable<Defer> {
    
    private static final long serialVersionUID = 1L;
    
    private final long start; // A data de criação do atraso.
    private int count = 0; // Quantas vezes houve um atraso.
    
    private Defer() {
        this.start = System.currentTimeMillis();
    }
    
    @Deprecated
    private Defer(long start) {
        this.start = start;
    }
    
    /**
     * Mapa de atrasos programados.
     */
    private static final HashMap<String,Defer> MAP = new HashMap<String,Defer>();
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean CHANGED = false;

    private static synchronized Defer dropExact(String token) {
        Defer ret = MAP.remove(token);
        if (ret != null) {
            CHANGED = true;
        }
        return ret;
    }

    private static synchronized Defer putExact(String key, Defer value) {
        Defer ret = MAP.put(key, value);
        if (!value.equals(ret)) {
            CHANGED = true;
        }
        return ret;
    }

    private static synchronized TreeSet<String> keySet() {
        TreeSet<String> keySet = new TreeSet<String>();
        keySet.addAll(MAP.keySet());
        return keySet;
    }

    private static synchronized HashMap<String,Defer> getMap() {
        HashMap<String,Defer> map = new HashMap<String,Defer>();
        map.putAll(MAP);
        return map;
    }

    private static boolean containsExact(String key) {
        return MAP.containsKey(key);
    }

    private static Defer getExact(String host) {
        return MAP.get(host);
    }

    private static synchronized boolean isChanged() {
        return CHANGED;
    }

    private static synchronized void setStored() {
        CHANGED = false;
    }

    private static synchronized void setLoaded() {
        CHANGED = false;
    }
    
    public static void dropExpired() {
        long expire = System.currentTimeMillis() - (5 * 24 * 60 * 60 * 1000); // Expira em cinco dias
        for (String id : keySet()) {
            Defer defer = getExact(id);
            if (defer != null && defer.start < expire) {
                drop(id);
            }
        }
    }

    private synchronized void addCount() {
        this.count++;
    }
    
    private synchronized int getCount() {
        return count;
    }

    public static boolean defer(String id, int minutes) {
        if (id == null) {
            return false;
        } else if (minutes == 0) {
            return false;
        } else {
            id = id.trim().toLowerCase();
            long now = System.currentTimeMillis();
            Defer defer = getExact(id);
            if (defer == null) {
                defer = add(id);
                defer.addCount();
                return true;
            } else if (defer.start < (now - minutes * 60 * 1000)) {
                end(id);
                return false;
            } else {
                defer.addCount();
                return true;
            }
        }
    }
    
    public static int count(String id) {
        Defer defer = getExact(id);
        if (defer == null) {
            return 0;
        } else {
            return defer.getCount();
        }
    }

    public static void end(String id) {
        long now = System.currentTimeMillis();
        if (dropExact(id) != null) {
            Server.logDefer(now, id, "END");
        }
    }

    private static void drop(String id) {
        long now = System.currentTimeMillis();
        if (dropExact(id) != null) {
            Server.logDefer(now, id, "EXPIRED");
        }
    }

    private static Defer add(String id) {
        Defer defer = new Defer();
        if (putExact(id, defer) == null) {
            Server.logDefer(defer.start, id, "START");
        }
        return defer;
    }

    public static void store() {
        if (isChanged()) {
            try {
                long time = System.currentTimeMillis();
                File file = new File("./data/defer.map");
                HashMap<String,Defer> map = getMap();
                FileOutputStream outputStream = new FileOutputStream(file);
                try {
                    SerializationUtils.serialize(map, outputStream);
                    setStored();
                } finally {
                    outputStream.close();
                }
                Server.logStore(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }

    public static void load() {
        long time = System.currentTimeMillis();
        File file = new File("./data/defer.map");
        if (file.exists()) {
            try {
                HashMap<String,Object> map;
                FileInputStream fileInputStream = new FileInputStream(file);
                try {
                    map = SerializationUtils.deserialize(fileInputStream);
                } finally {
                    fileInputStream.close();
                }
                for (String key : map.keySet()) {
                    Object value = map.get(key);
                    if (value instanceof Long) {
                        long start = (Long) value;
                        Defer defer = new Defer(start);
                        putExact(key, defer);
                    } else if (value instanceof Defer) {
                        Defer defer = (Defer) value;
                        putExact(key, defer);
                    }
                }
                setLoaded();
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }

    @Override
    public int compareTo(Defer other) {
        if (other == null) {
            return -1;
        } else {
            return Long.valueOf(this.start).compareTo(other.start);
        }
    }
}
