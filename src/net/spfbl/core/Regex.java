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

import java.util.LinkedList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Faster regex matcher.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Regex {
    
    private final Pattern PATTERN;
    
    public Regex(String regex) throws PatternSyntaxException {
        PATTERN = Pattern.compile(regex);
    }
    
    public String pattern() {
        return PATTERN.pattern();
    }
    
    @Override
    public String toString() {
        return PATTERN.toString();
    }
    
    private final LinkedList<Matcher> MATCHER_LIST = new LinkedList<>();
    
    private synchronized Matcher pollMatcher() {
        return MATCHER_LIST.poll();
    }
    
    private synchronized void addMatcher(Matcher matcher) {
        if (MATCHER_LIST.size() < 4) {
            MATCHER_LIST.add(matcher);
        }
    }
    
    public Matcher createMatcher(CharSequence input) {
        Matcher matcher = pollMatcher();
        if (matcher == null) {
            matcher = PATTERN.matcher(input);
        } else {
            matcher.reset(input);
        }
        return matcher;
    }
    
    public boolean offerMatcher(Matcher matcher) {
        if (matcher == null) {
            return false;
        } else if (matcher.pattern() == PATTERN) {
            addMatcher(matcher);
            return true;
        } else {
            return false;
        }
    }
    
    public boolean matches(CharSequence input) {
        if (input == null) {
            return false;
        } else {
            Matcher matcher = pollMatcher();
            if (matcher == null) {
                matcher = PATTERN.matcher(input);
            } else {
                matcher.reset(input);
            }
            boolean matches = matcher.matches();
            addMatcher(matcher);
            return matches;
        }
    }
    
    public static final Regex HOSTNAME = new Regex("^\\.?"
            + "(([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])"
            + "(\\.([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9]))*)"
            + "\\.?$"
    );
    
    public static final Regex IPV4 = new Regex("^"
                    + "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}"
                    + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
                    + "$"
    );
    
    public static final Regex IPV6 = new Regex("^"
                    + "([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
                    + "([0-9a-fA-F]{1,4}:){1,7}:|"
                    + "([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
                    + "([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
                    + "([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
                    + "([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
                    + "([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
                    + "[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
                    + ":((:[0-9a-fA-F]{1,4}){1,7}|:)|"
                    + "fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}"
                    + "$"
    );
    
    public static final Regex CIDRV4 = new Regex("^"
                    + "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]){1,3}\\.){1,3}"
                    + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])/[0-9]{1,2}"
                    + "$"
    );
    
    public static final Regex CIDRV6 = new Regex("^"
                    + "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
                    + "([0-9a-fA-F]{1,4}:){1,7}:|"
                    + "([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
                    + "([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
                    + "([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
                    + "([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
                    + "([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
                    + "[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
                    + ":((:[0-9a-fA-F]{1,4}){1,7}|:)|"
                    + "fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,})"
                    + "/[0-9]{1,3}$"
    );
    
    public static final Regex REVERSEV6 = new Regex("^"
                + "(\\.?[0-9a-fA-F]{1,4})"
                + "(\\.[0-9a-fA-F]{1,4}){31}"
                + "$\\.?"
    );
    
    public static final Regex VALID_EMAIL = new Regex("^"
            + "[0-9a-zA-Z_-][0-9a-zA-Z._+-]{0,63}"
            + "@"
            + "(([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])"
            + "(\\.([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9]))*)"
            + "$"
    );
    
    public static boolean isHostname(String address) {
        if (address == null) {
            return false;
        } else if (IPV4.matches(address)) {
            return false;
        } else {
            return HOSTNAME.matches(address);
        }
    }
    
    public static boolean isValidIPv4(String address) {
        return IPV4.matches(address);
    }
    
    public static boolean isValidIPv6(String address) {
        return IPV6.matches(address);
    }
    
    public static boolean isValidIP(String address) {
        if (address == null) {
            return false;
        } else if (IPV4.matches(address)) {
            return true;
        } else {
            return IPV6.matches(address);
        }
    }
    
    public static boolean isValidCIDRv4(String address) {
        return CIDRV4.matches(address);
    }
    
    public static boolean isValidCIDRv6(String address) {
        return CIDRV6.matches(address);
    }
    
    public static boolean isValidCIDR(String address) {
        if (address == null) {
            return false;
        } else if (CIDRV4.matches(address)) {
            return true;
        } else {
            return CIDRV6.matches(address);
        }
    }
    
    public static boolean isReverseIPv6(String address) {
        return REVERSEV6.matches(address);
    }
    
    public static boolean isValidEmail(String address) {
        if (address == null) {
            return false;
        } else if (address.length() > 256) {
            // RFC 5321: "The maximum total length of a 
            // reverse-path or forward-path is 256 characters"
            return false;
        } else if (address.contains("..")) {
            return false;
        } else {
            return VALID_EMAIL.matches(address);
        }
    }
    
    public static boolean isValidRecipient(String address) {
        if (address == null) {
            return false;
        } else if (address.length() > 256) {
            // RFC 5321: "The maximum total length of a 
            // reverse-path or forward-path is 256 characters"
            return false;
        } else if (address.contains("..")) {
            return false;
        } else if (VALID_EMAIL.matches(address)) {
            return true;
        } else if (address.toUpperCase().startsWith("SRS0=")) {
            int index1 = address.lastIndexOf('@');
            int index2 = address.lastIndexOf('=', index1);
            if (index2 > 0) {
                int index3 = address.lastIndexOf('=', index2-1);
                if (index3 > 0) {
                    String part = address.substring(index2+1, index1);
                    String domain = address.substring(index3+1, index2);
                    address = part + '@' + domain;
                    return VALID_EMAIL.matches(address);
                }
            }
            return false;
        } else {
            return false;
        }
    }
}
