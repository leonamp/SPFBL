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
import net.spfbl.core.ProcessException;
import net.spfbl.core.Server;
import net.spfbl.whois.Domain;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Representa a lista de destinários que o SPFBL não deve enviar mensagens de
 * e-mail.
 *
 * Nesta lista podem entrar endereços inexistentes ou com qualquer outro tipo de
 * problema de entrega.
 *
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class NoReply {

    /**
     * Conjunto de destinatarios de não envio.
     */
    private static final HashSet<String> SET = new HashSet<>();
    /**
     * Flag que indica se o cache foi modificado.
     */
    private static boolean CHANGED = false;

    private static synchronized boolean dropExact(String token) {
        if (SET.remove(token)) {
            CHANGED = true;
            return true;
        } else {
            return false;
        }
    }

    private static synchronized boolean addExact(String token) {
        if (SET.add(token)) {
            CHANGED = true;
            return true;
        } else {
            return false;
        }
    }

    private static synchronized TreeSet<String> getAll() throws ProcessException {
        TreeSet<String> blockSet = new TreeSet<>();
        blockSet.addAll(SET);
        return blockSet;
    }

    private static synchronized boolean containsExact(String address) {
        return SET.contains(address);
    }

    private static String normalize(String recipient) {
        if (recipient == null) {
            return null;
        } else if (Domain.isValidEmail(recipient)) {
            return recipient.toLowerCase();
        } else if (recipient.endsWith("@")) {
            return recipient.toLowerCase();
        } else if (recipient.startsWith("@") && Domain.containsDomain(recipient.substring(1))) {
            return recipient.toLowerCase();
        } else if (recipient.startsWith(".") && Domain.containsDomain(recipient.substring(1))) {
            return recipient.toLowerCase();
        } else {
            return null;
        }
    }

    public static boolean add(String address) throws ProcessException {
        if ((address = normalize(address)) == null) {
            throw new ProcessException("RECIPIENT INVALID");
        } else if (addExact(address)) {
            return true;
        } else {
            return false;
        }
    }

    public static TreeSet<String> dropAll() throws ProcessException {
        TreeSet<String> trapSet = new TreeSet<>();
        for (String trap : getAll()) {
            if (dropExact(trap)) {
                trapSet.add(trap);
            }
        }
        return trapSet;
    }

    public static boolean drop(String address) throws ProcessException {
        if ((address = normalize(address)) == null) {
            throw new ProcessException("RECIPIENT INVALID");
        } else if (dropExact(address)) {
            return true;
        } else {
            return false;
        }
    }

    public static TreeSet<String> getSet() throws ProcessException {
        TreeSet<String> trapSet = new TreeSet<>();
        for (String recipient : getAll()) {
            if (!recipient.contains(":")) {
                trapSet.add(recipient);
            }
        }
        return trapSet;
    }

    public static boolean contains(String address, boolean inexistent) {
        if (address == null) {
            return false;
        } else if (address.contains("bounce+")) {
            return true;
        } else if (address.contains("bounce-")) {
            return true;
        } else if (address.contains("bounces-")) {
            return true;
        } else if (address.contains("-bounces@")) {
            return true;
        } else if (address.contains("-noreply@")) {
            return true;
        } else if (address.startsWith("mailer-daemon@")) {
            return true;
        } else if (address.startsWith("return-")) {
            return true;
        } else if (address.startsWith("noreply-")) {
            return true;
        } else if (address.startsWith("no-reply=")) {
            return true;
        } else if (address.startsWith("prvs=")) {
            return true;
        } else if (address.startsWith("msprvs1=")) {
            return true;
        } else if (!Domain.isValidEmail(address)) {
            return false;
        } else if (containsExact(address)) {
            return true;
        } else if (inexistent && Trap.contaisAnything(address)) {
            return true;
        } else {
            address = address.toLowerCase();
            int index1 = address.indexOf('@');
            int index2 = address.lastIndexOf('@');
            String recipient = address.substring(0, index1 + 1);
            String domain = address.substring(index2);
            if (containsExact(recipient)) {
                return true;
            } else if (containsExact(domain)) {
                return true;
            } else {
                int index3 = domain.length();
                while ((index3 = domain.lastIndexOf('.', index3 - 1)) > index2) {
                    String subdomain = domain.substring(0, index3 + 1);
                    if (containsExact(subdomain)) {
                        return true;
                    }
                }
                int index4 = recipient.length();
                while ((index4 = recipient.lastIndexOf('.', index4 - 1)) > index2) {
                    String subrecipient = recipient.substring(0, index4 + 1);
                    if (containsExact(subrecipient)) {
                        return true;
                    }
                }
                domain = '.' + domain.substring(1);
                int index5 = 0;
                while ((index5 = domain.indexOf('.', index5)) != -1) {
                    String subdomain = domain.substring(index5++);
                    if (containsExact(subdomain)) {
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
                File file = new File("./data/noreply.set");
                TreeSet<String> set = getAll();
                try (FileOutputStream outputStream = new FileOutputStream(file)) {
                    SerializationUtils.serialize(set, outputStream);
                    CHANGED = false;
                }
                Server.logStore(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }

    public static void load() {
        long time = System.currentTimeMillis();
        File file = new File("./data/noreply.set");
        if (file.exists()) {
            try {
                Set<String> set;
                try (FileInputStream fileInputStream = new FileInputStream(file)) {
                    set = SerializationUtils.deserialize(fileInputStream);
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
