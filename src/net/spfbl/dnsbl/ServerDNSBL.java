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

package net.spfbl.dnsbl;

import java.io.Serializable;
import java.util.Locale;
import net.spfbl.core.Core;
import net.spfbl.whois.Domain;

/**
 * Servidor DNSBL que este serviço responde.
 *
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class ServerDNSBL implements Serializable, Comparable<ServerDNSBL> {

    private static final long serialVersionUID = 1L;

    private final String hostname;
    private String message;

    public ServerDNSBL(String hostname, String message) {
        this.hostname = hostname;
        this.message = message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
    
    public boolean isHostName(String hostname) {
        return this.hostname.equals(Domain.normalizeHostname(hostname, true));
    }

    public String getHostName() {
        return hostname;
    }
    
    public String getMessage() {
        return message;
    }

    @Override
    public int compareTo(ServerDNSBL other) {
        if (other == null) {
            return -1;
        } else {
            return this.hostname.compareTo(other.hostname);
        }
    }

    @Override
    public String toString() {
        return hostname;
    }

    public String extractDomain(String host) {
        if ((host = Domain.normalizeHostname(host, true)) == null) {
            return null;
        } else if (host.equals(this.hostname)) {
            return null;
        } else if (host.endsWith(this.hostname)) {
            int index = host.length() - this.hostname.length();
            String result = host.substring(0, index);
            if (Domain.isHostname(result)) {
                return result;
            } else {
                return null;
            }
        } else {
            return null;
        }
    }

}
