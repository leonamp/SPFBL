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

package net.spfbl.data;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;
import net.spfbl.core.Client;
import net.spfbl.core.ProcessException;
import net.spfbl.core.Server;
import net.spfbl.whois.Domain;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Representa a lista de spamtrap do sistema.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Trap {
    
    /**
     * Conjunto de destinatarios de spamtrap.
     */
    private static final HashSet<String> SET = new HashSet<String>();
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean CHANGED = false;

    private static boolean dropExact(String token) {
        if (SET.remove(token)) {
            CHANGED = true;
            return true;
        } else {
            return false;
        }
    }

    private static boolean addExact(String token) {
        if (SET.add(token)) {
            CHANGED = true;
            return true;
        } else {
            return false;
        }
    }

    public static TreeSet<String> getAll() throws ProcessException {
        TreeSet<String> blockSet = new TreeSet<String>();
        blockSet.addAll(SET);
        return blockSet;
    }

    public static boolean containsExact(String address) {
        return SET.contains(address);
    }

    public static boolean isValid(String recipient) {
        if (recipient == null) {
            return false;
        } else if (Domain.isEmail(recipient)) {
            return true;
        } else if (recipient.startsWith("@") && Domain.containsDomain(recipient.substring(1))) {
            return true;
        } else {
            return false;
        }
    }

    public static boolean add(String recipient) throws ProcessException {
        if (!isValid(recipient)) {
            throw new ProcessException("ERROR: RECIPIENT INVALID");
        } else if (addExact(recipient.toLowerCase())) {
            return true;
        } else {
            return false;
        }
    }

    public static boolean add(Client client, String recipient) throws ProcessException {
        if (client == null || !client.hasEmail()) {
            throw new ProcessException("ERROR: CLIENT INVALID");
        } else if (!isValid(recipient)) {
            throw new ProcessException("ERROR: RECIPIENT INVALID");
        } else if (addExact(client.getEmail() + ':' + recipient.toLowerCase())) {
            return true;
        } else {
            return false;
        }
    }

    public static TreeSet<String> dropAll() throws ProcessException {
        TreeSet<String> trapSet = new TreeSet<String>();
        for (String trap : getAll()) {
            if (dropExact(trap)) {
                trapSet.add(trap);
            }
        }
        return trapSet;
    }

    public static boolean drop(String recipient) throws ProcessException {
        if (!isValid(recipient)) {
            throw new ProcessException("ERROR: RECIPIENT INVALID");
        } else if (dropExact(recipient.toLowerCase())) {
            return true;
        } else {
            return false;
        }
    }

    public static boolean drop(Client client, String recipient) throws ProcessException {
        if (client == null || !client.hasEmail()) {
            throw new ProcessException("ERROR: CLIENT INVALID");
        } else if (!isValid(recipient)) {
            throw new ProcessException("ERROR: RECIPIENT INVALID");
        } else if (dropExact(client.getEmail() + ':' + recipient.toLowerCase())) {
            return true;
        } else {
            return false;
        }
    }

    public static TreeSet<String> get(Client client) throws ProcessException {
        TreeSet<String> trapSet = new TreeSet<String>();
        if (client != null && client.hasEmail()) {
            for (String recipient : getAll()) {
                if (recipient.startsWith(client.getEmail() + ':')) {
                    int index = recipient.indexOf(':') + 1;
                    recipient = recipient.substring(index);
                    trapSet.add(recipient);
                }
            }
        }
        return trapSet;
    }

    public static TreeSet<String> get() throws ProcessException {
        TreeSet<String> trapSet = new TreeSet<String>();
        for (String recipient : getAll()) {
            if (!recipient.contains(":")) {
                trapSet.add(recipient);
            }
        }
        return trapSet;
    }

    public static boolean contains(Client client, String recipient) {
        if (client == null) {
            return false;
        } else if (!client.hasEmail()) {
            return false;
        } else if (!isValid(recipient)) {
            return false;
        } else {
            recipient = recipient.toLowerCase();
            int index2 = recipient.lastIndexOf('@');
            String domain = recipient.substring(recipient.lastIndexOf('@'));
            if (containsExact(recipient)) {
                return true;
            } else if (containsExact(domain)) {
                return true;
            } else if (containsExact(client.getEmail() + ':' + recipient)) {
                return true;
            } else if (containsExact(client.getEmail() + ':' + domain)) {
                return true;
            } else {
                int index3 = domain.length();
                while ((index3 = domain.lastIndexOf('.', index3 - 1)) > index2) {
                    String subdomain = domain.substring(0, index3 + 1);
                    if (containsExact(subdomain)) {
                        return true;
                    } else if (containsExact(client.getEmail() + ':' + subdomain)) {
                        return true;
                    }
                }
                int index4 = recipient.length();
                while ((index4 = recipient.lastIndexOf('.', index4 - 1)) > index2) {
                    String subrecipient = recipient.substring(0, index4 + 1);
                    if (containsExact(subrecipient)) {
                        return true;
                    } else if (containsExact(client.getEmail() + ':' + subrecipient)) {
                        return true;
                    }
                }
                return false;
            }
        }
    }

    public static void store() {
        if (CHANGED) {
            try {
                long time = System.currentTimeMillis();
                File file = new File("./data/trap.set");
                TreeSet<String> set = getAll();
                FileOutputStream outputStream = new FileOutputStream(file);
                try {
                    SerializationUtils.serialize(set, outputStream);
                    CHANGED = false;
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
        File file = new File("./data/trap.set");
        if (file.exists()) {
            try {
                Set<String> set;
                FileInputStream fileInputStream = new FileInputStream(file);
                try {
                    set = SerializationUtils.deserialize(fileInputStream);
                } finally {
                    fileInputStream.close();
                }
                for (String token : set) {
                    addExact(token);
                }
                CHANGED = false;
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
}
