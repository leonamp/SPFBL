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
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import net.spfbl.core.Client;
import net.spfbl.core.ProcessException;
import net.spfbl.core.Server;
import net.spfbl.core.User;
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
//    private static final HashSet<String> SET = new HashSet<String>();
    private static final HashMap<String,Long> MAP = new HashMap<String,Long>();
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean CHANGED = false;

    private synchronized static boolean dropExact(String token) {
        if (token == null) {
            return false;
        } else if (MAP.remove(token) == null) {
            return false;
        } else {
            CHANGED = true;
            return true;
        }
    }
    
    public static boolean putTrap(String client, String token, String timeString) throws ProcessException {
        if (!Domain.isValidEmail(client)) {
            throw new ProcessException("INVALID USER");
        } else if (!isValid(token)) {
            throw new ProcessException("INVALID TRAP");
        } else {
            try {
                Long time = timeString == null ? 0L : Long.parseLong(timeString);
                return putExact(client.toLowerCase() + ':' + token.toLowerCase(), time);
            } catch (NumberFormatException ex) {
                throw new ProcessException("INVALID TIME", ex);
            }
        }
    }
    
    public static boolean putInexistent(String client, String token, String timeString) throws ProcessException {
        if (!Domain.isValidEmail(client)) {
            throw new ProcessException("INVALID USER");
        } else if (!isValid(token)) {
            throw new ProcessException("INVALID ADDRESS");
        } else {
            try {
                long time = timeString == null ? System.currentTimeMillis() + 31536000000L : Long.parseLong(timeString);
                if (time < System.currentTimeMillis()) {
                    throw new ProcessException("INVALID TIME");
                } else {
                    return putExact(client.toLowerCase() + ':' + token.toLowerCase(), time);
                }
            } catch (NumberFormatException ex) {
                throw new ProcessException("INVALID TIME", ex);
            }
        }
    }
    
    public static boolean putTrap(String token, String timeString) throws ProcessException {
        if (!isValid(token)) {
            throw new ProcessException("INVALID TRAP");
        } else {
            try {
                Long time = timeString == null ? 0L : Long.parseLong(timeString);
                return putExact(token.toLowerCase(), time);
            } catch (NumberFormatException ex) {
                throw new ProcessException("INVALID TIME", ex);
            }
        }
    }
    
    public static boolean putInexistent(String token, String timeString) throws ProcessException {
        if (!isValid(token)) {
            throw new ProcessException("INVALID ADDRESS");
        } else {
            try {
                long time = timeString == null ? System.currentTimeMillis() + 31536000000L : Long.parseLong(timeString);
                if (time < System.currentTimeMillis()) {
                    throw new ProcessException("INVALID TIME");
                } else {
                    return putExact(token.toLowerCase(), time);
                }
            } catch (NumberFormatException ex) {
                throw new ProcessException("INVALID TIME", ex);
            }
        }
    }
    
    private synchronized static boolean putExact(String token, Long timeNew) {
        if (token == null || timeNew == null) {
            return false;
        } else {
            Long timeOld = MAP.put(token, timeNew);
            if (timeOld == null) {
                return CHANGED = true;
            } else {
                long timeNow = System.currentTimeMillis();
                boolean changed = timeOld < timeNow != timeNew < timeNow;
                CHANGED |= changed;
                return changed;
            }
        }
    }

    private synchronized static boolean addTrapExact(String token) {
        if (token == null) {
            return false;
        } else {
            Long time = MAP.put(token, 0L);
            if (time == null || !time.equals(0L)) {
                return CHANGED = true;
            } else {
                return false;
            }
        }
    }

    public synchronized static TreeSet<String> getTrapAllSet() {
        TreeSet<String> blockSet = new TreeSet<String>();
        for (String key : MAP.keySet()) {
            if (System.currentTimeMillis() > MAP.get(key)) {
                blockSet.add(key);
            }
        }
        return blockSet;
    }
    
    public synchronized static TreeSet<String> getInexistentAllSet() {
        TreeSet<String> blockSet = new TreeSet<String>();
        for (String key : MAP.keySet()) {
            if (System.currentTimeMillis() <= MAP.get(key)) {
                blockSet.add(key);
            }
        }
        return blockSet;
    }
    
    public synchronized static Long getTime(String address) {
        if (address == null) {
            return null;
        } else {
            return MAP.get(address);
        }
    }
    
    public synchronized static HashMap<String,Long> getMap() {
        HashMap<String,Long> map = new HashMap<String,Long>();
        map.putAll(MAP);
        return map;
    }

    public synchronized static boolean containsTrapExact(String address) {
        return System.currentTimeMillis() > MAP.get(address);
    }
    
    public synchronized static boolean containsInexistentExact(String address) {
        return System.currentTimeMillis() <= MAP.get(address);
    }
    
    public synchronized static boolean containsAnythingExact(String address) {
        return MAP.containsKey(address);
    }

    public static boolean isValid(String recipient) {
        if (recipient == null) {
            return false;
        } else if (Domain.isValidEmail(recipient)) {
            return true;
        } else {
            return recipient.startsWith("@") && Domain.containsDomain(recipient.substring(1));
        }
    }

    public static boolean addTrap(String recipient) throws ProcessException {
        if (!isValid(recipient)) {
            throw new ProcessException("RECIPIENT INVALID");
        } else {
            return addTrapExact(recipient.toLowerCase());
        }
    }

    public static boolean addTrap(Client client, String recipient) throws ProcessException {
        if (client == null || !client.hasEmail()) {
            throw new ProcessException("CLIENT INVALID");
        } else if (!isValid(recipient)) {
            throw new ProcessException("RECIPIENT INVALID");
        } else {
            return addTrapExact(client.getEmail() + ':' + recipient.toLowerCase());
        }
    }
    
    public static boolean addTrap(String client, String recipient) throws ProcessException {
        if (client == null || !Domain.isValidEmail(client)) {
            throw new ProcessException("CLIENT INVALID");
        } else if (!isValid(recipient)) {
            throw new ProcessException("RECIPIENT INVALID");
        } else {
            return addTrapExact(client + ':' + recipient.toLowerCase());
        }
    }
    
    public static boolean addInexistentForever(String recipient) {
        if (!isValid(recipient)) {
            return false;
        } else {
            return putExact(recipient.toLowerCase(), Long.MAX_VALUE);
        }
    }
    
    public static boolean addInexistentSafe(User user, String recipient) {
        if (user == null) {
            return false;
        } else if (!isValid(recipient)) {
            return false;
        } else {
            long time = System.currentTimeMillis() + 31536000000L;
            return putExact(user.getEmail() + ':' + recipient.toLowerCase(), time);
        }
    }
    
    public static boolean addInexistent(User user, String recipient) throws ProcessException {
        if (user == null) {
            throw new ProcessException("USER INVALID");
        } else if (!isValid(recipient)) {
            throw new ProcessException("RECIPIENT INVALID");
        } else {
            long time = System.currentTimeMillis() + 31536000000L;
            return putExact(user.getEmail() + ':' + recipient.toLowerCase(), time);
        }
    }
    
    public static boolean addInexistentForever(User user, String recipient) {
        if (user == null) {
            return false;
        } else if (!isValid(recipient)) {
            return false;
        } else {
            return putExact(user.getEmail() + ':' + recipient.toLowerCase(), Long.MAX_VALUE);
        }
    }
    
    public static boolean addInexistent(Client client, String recipient) throws ProcessException {
        if (client == null || !client.hasEmail()) {
            throw new ProcessException("CLIENT INVALID");
        } else if (!isValid(recipient)) {
            throw new ProcessException("RECIPIENT INVALID");
        } else {
            long time = System.currentTimeMillis() + 31536000000L;
            return putExact(client.getEmail() + ':' + recipient.toLowerCase(), time);
        }
    }

    public static TreeSet<String> dropTrapAll() throws ProcessException {
        TreeSet<String> trapSet = new TreeSet<String>();
        for (String trap : getTrapAllSet()) {
            if (dropExact(trap)) {
                trapSet.add(trap);
            }
        }
        return trapSet;
    }
    
    public static TreeSet<String> dropInexistentAll() throws ProcessException {
        TreeSet<String> trapSet = new TreeSet<String>();
        for (String trap : getInexistentAllSet()) {
            if (dropExact(trap)) {
                trapSet.add(trap);
            }
        }
        return trapSet;
    }
    
    public static boolean clear(User user, String address) throws ProcessException {
        if (isValid(address)) {
            int index = address.indexOf('@');
            String domain = address.substring(index);
            boolean dropped = drop(address);
            dropped |= drop(domain);
            if (user != null) {
                dropped |= drop(user, address);
                dropped |= drop(user, domain);
            }
            return dropped;
        } else {
            return false;
        }
    }
    
    public static boolean clear(
            Client client,
            User user,
            String address
    ) throws ProcessException {
        if (isValid(address)) {
            int index = address.indexOf('@');
            String domain = address.substring(index);
            boolean dropped = drop(address);
            dropped |= drop(domain);
            if (user != null) {
                dropped |= drop(user, address);
                dropped |= drop(user, domain);
            }
            if (client != null) {
                dropped |= drop(client, address);
                dropped |= drop(client, domain);
            }
            return dropped;
        } else {
            return false;
        }
    }
    
    public static boolean clear(
            TreeSet<String> clientSet,
            User user,
            String address
    ) throws ProcessException {
        if (isValid(address)) {
            int index = address.indexOf('@');
            String domain = address.substring(index);
            boolean dropped = drop(address);
            dropped |= drop(domain);
            if (user != null) {
                dropped |= drop(user, address);
                dropped |= drop(user, domain);
            }
            if (clientSet != null) {
                for (String client : clientSet) {
                    dropped |= drop(client, address);
                    dropped |= drop(client, domain);
                }
            }
            return dropped;
        } else {
            return false;
        }
    }

    public static boolean drop(String recipient) throws ProcessException {
        if (!isValid(recipient)) {
            throw new ProcessException("RECIPIENT INVALID");
        } else {
            return dropExact(recipient.toLowerCase());
        }
    }
    
    public static boolean drop(User user, String recipient) throws ProcessException {
        if (user == null) {
            throw new ProcessException("USER INVALID");
        } else if (!isValid(recipient)) {
            throw new ProcessException("RECIPIENT INVALID");
        } else {
            boolean dropped = dropExact(user.getEmail() + ':' + recipient.toLowerCase());
            if (Domain.isValidEmail(recipient)) {
                dropped |= dropExact(recipient.toLowerCase());
                if (user.isPostmaster()) {
                    for (User localUser : User.getSet()) {
                        dropped |= dropExact(localUser.getEmail() + ':' + recipient.toLowerCase());
                    }
                }
            }
            return dropped;
        }
    }

    public static boolean drop(Client client, String recipient) throws ProcessException {
        if (client == null || !client.hasEmail()) {
            throw new ProcessException("CLIENT INVALID");
        } else if (!isValid(recipient)) {
            throw new ProcessException("RECIPIENT INVALID");
        } else {
            boolean dropped = dropExact(client.getEmail() + ':' + recipient.toLowerCase());
            if (Domain.isValidEmail(recipient)) {
                dropped |= dropExact(recipient.toLowerCase());
            }
            return dropped;
        }
    }
    
    public static boolean drop(User user, Client client, String recipient) throws ProcessException {
        boolean dropped = drop(client, recipient);
        return dropped |= drop(user, recipient);
    }
    
    public static boolean drop(String client, String recipient) throws ProcessException {
        if (client == null || !Domain.isValidEmail(client)) {
            throw new ProcessException("CLIENT INVALID");
        } else if (!isValid(recipient)) {
            throw new ProcessException("RECIPIENT INVALID");
        } else {
            boolean dropped = dropExact(client + ':' + recipient.toLowerCase());
            if (Domain.isValidEmail(recipient)) {
                dropped |= dropExact(recipient.toLowerCase());
            }
            return dropped;
        }
    }

    public static TreeSet<String> getTrapSet(Client client) throws ProcessException {
        TreeSet<String> trapSet = new TreeSet<String>();
        if (client != null && client.hasEmail()) {
            for (String recipient : getTrapAllSet()) {
                if (recipient.startsWith(client.getEmail() + ':')) {
                    int index = recipient.indexOf(':') + 1;
                    recipient = recipient.substring(index);
                    trapSet.add(recipient);
                }
            }
        }
        return trapSet;
    }
    
    public static TreeSet<String> getInexistentSet(Client client) throws ProcessException {
        TreeSet<String> trapSet = new TreeSet<String>();
        if (client != null && client.hasEmail()) {
            for (String recipient : getInexistentAllSet()) {
                if (recipient.startsWith(client.getEmail() + ':')) {
                    int index = recipient.indexOf(':') + 1;
                    recipient = recipient.substring(index);
                    trapSet.add(recipient);
                }
            }
        }
        return trapSet;
    }

    public static TreeSet<String> getTrapSet() throws ProcessException {
        TreeSet<String> trapSet = new TreeSet<String>();
        for (String recipient : getTrapAllSet()) {
            if (!recipient.contains(":")) {
                trapSet.add(recipient);
            }
        }
        return trapSet;
    }
    
    public static TreeSet<String> getInexistentSet() throws ProcessException {
        TreeSet<String> trapSet = new TreeSet<String>();
        for (String recipient : getInexistentAllSet()) {
            if (!recipient.contains(":")) {
                trapSet.add(recipient);
            }
        }
        return trapSet;
    }

    public static boolean containsTrap(Client client, User user, String recipient) {
        // Definição do e-mail do usuário.
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        } else if (client != null) {
            userEmail = client.getEmail();
        }
        if (userEmail == null) {
            return false;
        } else if (!isValid(recipient)) {
            return false;
        } else {
            recipient = recipient.toLowerCase();
            int index2 = recipient.lastIndexOf('@');
            String domain = recipient.substring(recipient.lastIndexOf('@'));
            if (containsTrapExact(recipient)) {
                return true;
            } else if (containsTrapExact(domain)) {
                return true;
            } else if (containsTrapExact(userEmail + ':' + recipient)) {
                return true;
            } else if (containsTrapExact(userEmail + ':' + domain)) {
                return true;
            } else {
                int index3 = domain.length();
                while ((index3 = domain.lastIndexOf('.', index3 - 1)) > index2) {
                    String subdomain = domain.substring(0, index3 + 1);
                    if (containsTrapExact(subdomain)) {
                        return true;
                    } else if (containsTrapExact(userEmail + ':' + subdomain)) {
                        return true;
                    }
                }
                int index4 = recipient.length();
                while ((index4 = recipient.lastIndexOf('.', index4 - 1)) > index2) {
                    String subrecipient = recipient.substring(0, index4 + 1);
                    if (containsTrapExact(subrecipient)) {
                        return true;
                    } else if (containsTrapExact(userEmail + ':' + subrecipient)) {
                        return true;
                    }
                }
                return false;
            }
        }
    }
    
    public static boolean containsInexistent(Client client, User user, String recipient) {
        // Definição do e-mail do usuário.
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        } else if (client != null) {
            userEmail = client.getEmail();
        }
        if (userEmail == null) {
            return false;
        } else if (!isValid(recipient)) {
            return false;
        } else {
            recipient = recipient.toLowerCase();
            int index2 = recipient.lastIndexOf('@');
            String domain = recipient.substring(recipient.lastIndexOf('@'));
            if (containsInexistentExact(recipient)) {
                return true;
            } else if (containsInexistentExact(domain)) {
                return true;
            } else if (containsInexistentExact(userEmail + ':' + recipient)) {
                return true;
            } else if (containsInexistentExact(userEmail + ':' + domain)) {
                return true;
            } else {
                int index3 = domain.length();
                while ((index3 = domain.lastIndexOf('.', index3 - 1)) > index2) {
                    String subdomain = domain.substring(0, index3 + 1);
                    if (containsInexistentExact(subdomain)) {
                        return true;
                    } else if (containsInexistentExact(userEmail + ':' + subdomain)) {
                        return true;
                    }
                }
                int index4 = recipient.length();
                while ((index4 = recipient.lastIndexOf('.', index4 - 1)) > index2) {
                    String subrecipient = recipient.substring(0, index4 + 1);
                    if (containsInexistentExact(subrecipient)) {
                        return true;
                    } else if (containsInexistentExact(userEmail + ':' + subrecipient)) {
                        return true;
                    }
                }
                return false;
            }
        }
    }
    
    public static boolean containsAnything(Client client, User user, String recipient) {
        if (!isValid(recipient)) {
            return false;
        } else {
            recipient = recipient.toLowerCase();
            int index2 = recipient.lastIndexOf('@');
            String domain = recipient.substring(recipient.lastIndexOf('@'));
            String emailClient = client == null ? null : client.getEmail();
            String emailUser = user == null ? null : user.getEmail();
            if (containsAnythingExact(recipient)) {
                return true;
            } else if (containsAnythingExact(domain)) {
                return true;
            } else if (emailClient != null && containsAnythingExact(emailClient + ':' + recipient)) {
                return true;
            } else if (emailClient != null && containsAnythingExact(emailClient + ':' + domain)) {
                return true;
            } else if (emailUser != null && containsAnythingExact(emailUser + ':' + recipient)) {
                return true;
            } else if (emailUser != null && containsAnythingExact(emailUser + ':' + domain)) {
                return true;
            } else {
                int index3 = domain.length();
                while ((index3 = domain.lastIndexOf('.', index3 - 1)) > index2) {
                    String subdomain = domain.substring(0, index3 + 1);
                    if (containsAnythingExact(subdomain)) {
                        return true;
                    } else if (emailClient != null && containsAnythingExact(emailClient + ':' + subdomain)) {
                        return true;
                    } else if (emailUser != null && containsAnythingExact(emailUser + ':' + subdomain)) {
                        return true;
                    }
                }
                int index4 = recipient.length();
                while ((index4 = recipient.lastIndexOf('.', index4 - 1)) > index2) {
                    String subrecipient = recipient.substring(0, index4 + 1);
                    if (containsAnythingExact(subrecipient)) {
                        return true;
                    } else if (emailClient != null && containsAnythingExact(emailClient + ':' + subrecipient)) {
                        return true;
                    } else if (emailUser != null && containsAnythingExact(emailUser + ':' + subrecipient)) {
                        return true;
                    }
                }
                return false;
            }
        }
    }
    
    public static boolean contaisAnything(String recipient) {
        return getTime(null, null, recipient) != null;
    }
    
    public static Long getTime(Client client, String recipient) {
        if (client == null) {
            return null;
        } else {
            return getTime(client.getEmail(), recipient);
        }
    }
    
    public static Long getTime(User user, String recipient) {
        if (user == null) {
            return null;
        } else {
            return getTime(user.getEmail(), recipient);
        }
    }
    
    public static Long getTime(Client client, User user, String recipient) {
        // Definição do e-mail do usuário.
        String userEmail = null;
        if (user != null) {
            userEmail = user.getEmail();
        } else if (client != null) {
            userEmail = client.getEmail();
        }
        return getTime(userEmail, recipient);
    }
    
    public static Long getTimeRecipient(Client client, User user, String recipient) {
        if (Domain.isValidEmail(recipient)) {
            Long timeClient = getTime(client, recipient);
            Long timeUser = getTime(user, recipient);
            if (timeClient == null) {
                return timeUser;
            } else if (timeUser == null) {
                return timeClient;
            } else {
                return Math.min(timeClient, timeUser);
            }
        } else {
            return Long.MAX_VALUE;
        }
    }
    
    public static Long getTime(String userEmail, String recipient) {
        if (!isValid(recipient)) {
            return null;
        } else {
            recipient = recipient.toLowerCase();
            int index2 = recipient.lastIndexOf('@');
            String domain = recipient.substring(recipient.lastIndexOf('@'));
            Long time;
            if ((time = Trap.getTime(recipient)) != null) {
                return time;
            } else if ((time = Trap.getTime(domain)) != null) {
                return time;
            } else if (userEmail != null && (time = Trap.getTime(userEmail + ':' + recipient)) != null) {
                return time;
            } else if (userEmail != null && (time = Trap.getTime(userEmail + ':' + domain)) != null) {
                return time;
            } else {
                int index3 = domain.length();
                while ((index3 = domain.lastIndexOf('.', index3 - 1)) > index2) {
                    String subdomain = domain.substring(0, index3 + 1);
                    if ((time = Trap.getTime(subdomain)) != null) {
                        return time;
                    } else if (userEmail != null && (time = Trap.getTime(userEmail + ':' + subdomain)) != null) {
                        return time;
                    }
                }
                int index4 = recipient.length();
                while ((index4 = recipient.lastIndexOf('.', index4 - 1)) > index2) {
                    String subrecipient = recipient.substring(0, index4 + 1);
                    if ((time = Trap.getTime(subrecipient)) != null) {
                        return time;
                    } else if (userEmail != null && (time = Trap.getTime(userEmail + ':' + subrecipient)) != null) {
                        return time;
                    }
                }
                return null;
            }
        }
    }

    public static void store() {
        if (CHANGED) {
            try {
//                Server.logTrace("storing trap.map");
                long time = System.currentTimeMillis();
                File file = new File("./data/trap.map");
                HashMap<String,Long> map = getMap();
                FileOutputStream outputStream = new FileOutputStream(file);
                try {
                    SerializationUtils.serialize(map, outputStream);
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
        File file = new File("./data/trap.map");
        if (file.exists()) {
            try {
                Map<String,Long> map;
                FileInputStream fileInputStream = new FileInputStream(file);
                try {
                    map = SerializationUtils.deserialize(fileInputStream);
                } finally {
                    fileInputStream.close();
                }
                for (String token : map.keySet()) {
                    Long time2 = map.get(token);
                    putExact(token, time2);
                }
                CHANGED = false;
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
}
