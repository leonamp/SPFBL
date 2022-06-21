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

package net.spfbl.data;

import java.util.TreeSet;
import net.spfbl.core.Client;
import net.spfbl.core.Core;
import static net.spfbl.core.Regex.isHostname;
import static net.spfbl.core.Regex.isValidIP;
import net.spfbl.core.User;
import static net.spfbl.data.Reputation.Flag.BENEFICIAL;
import static net.spfbl.data.Reputation.Flag.HARMFUL;
import static net.spfbl.data.Reputation.Flag.UNACCEPTABLE;
import static net.spfbl.data.Reputation.Flag.UNDESIRABLE;
import net.spfbl.spf.SPF.Qualifier;

/**
 * Representa a estrutura de reputação dos sistemas de envio.
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Reputation {

    private float xiSum;
    private float xi2Sum;
    private int last;
    private Object flag;
    private byte minimum;
    private byte maximum;

    public static enum Flag {

        HARMFUL, // -4
        UNDESIRABLE, // -2
        UNACCEPTABLE, // -1

        ACCEPTABLE, // 1
        DESIRABLE, // 2
        BENEFICIAL; // 4// 4
        
        public static String getName(Flag flag) {
            if (flag == null) {
                return null;
            } else {
                return flag.name();
            }
        }
        
        public static Flag getFlag(byte value) {
            if (value <= -4) {
                return Flag.HARMFUL;
            } else if (value >= 4) {
                return Flag.BENEFICIAL;
            } else if (value <= -3) {
                return Flag.UNDESIRABLE;
            } else if (value >= 3) {
                return Flag.DESIRABLE;
            } else if (value < 0) {
                return Flag.UNACCEPTABLE;
            } else {
                return Flag.ACCEPTABLE;
            }
        }
        
        public static Flag getFlag(float value) {
            if (value < -3) {
                return Flag.HARMFUL;
            } else if (value > 3) {
                return Flag.BENEFICIAL;
            } else if (value < -1.5) {
                return Flag.UNDESIRABLE;
            } else if (value > 1.5) {
                return Flag.DESIRABLE;
            } else if (value < 0) {
                return Flag.UNACCEPTABLE;
            } else {
                return Flag.ACCEPTABLE;
            }
        }
        
        public static Flag getFlag(String name) {
            if (name == null) {
                return null;
            } else {
                try {
                    return Flag.valueOf(name);
                } catch (IllegalArgumentException ex) {
                    return null;
                }
            }
        }
        
        public static byte getValue(String name) {
            if (name == null) {
                return 0;
            } else {
                Flag flag = getFlag(name);
                return getValue(flag);
            }
        }
        
        public static byte getValue(Flag flag) {
            if (flag == null) {
                return 0;
            } else {
                switch (flag) {
                    case HARMFUL:
                        return -4;
                    case UNDESIRABLE:
                        return -2;
                    case UNACCEPTABLE:
                        return -1;
                    case ACCEPTABLE:
                        return 1;
                    case DESIRABLE:
                        return 2;
                    case BENEFICIAL:
                        return 4;
                    default:
                        return 0;
                }
            }
        }
        
        public boolean isBetween(byte minimum, byte maximun) {
            switch (this) {
                case HARMFUL:
                    return minimum <= -4 && maximun >= -4;
                case UNDESIRABLE:
                    return minimum <= -2 && maximun >= -2;
                case UNACCEPTABLE:
                    return minimum <= -1 && maximun >= -1;
                case ACCEPTABLE:
                    return minimum <= 1 && maximun >= 1;
                case DESIRABLE:
                    return minimum <= 2 && maximun >= 2;
                case BENEFICIAL:
                    return minimum <= 4 && maximun >= 4;
                default:
                    return false;
            }
        }
        
        @Override
        public String toString() {
            return name();
        }
    }
    
    private static final Integer ZERO = 0;
    
    protected Reputation() {
        this.xiSum = 0.0f;
        this.xi2Sum = 0.0f;
        this.last = TIME;
        this.flag = ZERO;
        this.minimum = 0;
        this.maximum = 0;
    }

    protected Reputation(Reputation other, float ajust) {
        float[] xiResult = other.getXiSum();
        this.xiSum = xiResult[0] / ajust;
        this.xi2Sum = xiResult[1] / ajust;
        this.last = TIME;
        this.flag = ZERO;
        this.minimum = other.minimum;
        this.maximum = other.maximum;
    }
    
    private static Object parseFlag(String value) {
        Object flag = Core.getInteger(value);
        if (flag == null) {
            try {
                flag = Flag.valueOf(value);
            } catch (Exception ex) {
                flag = ZERO;
            }
        }
        return flag;
    }
    
    public static Reputation newReputation(
                float xiSum,
                float xi2Sum,
                int last,
                String flag,
                byte minimum,
                byte maximum
        ) {
        Reputation reputation = new Reputation();
        reputation.set(xiSum, xi2Sum, last, flag, minimum, maximum);
        return reputation;
    }
    
    protected synchronized void set(
                float xiSum,
                float xi2Sum,
                int last,
                String flag,
                byte minimum,
                byte maximum
        ) {
        this.xiSum = xiSum;
        this.xi2Sum = xi2Sum;
        this.last = last;
        this.flag = parseFlag(flag);
        this.minimum = minimum;
        this.maximum = maximum;
    }
    
    private static int TIME = (int) (System.currentTimeMillis() >>> 32);

    public static void refreshTime() {
        TIME = (int) (System.currentTimeMillis() >>> 32);
    }
    
    protected int getLast() {
        return last;
    }
    
    protected boolean isExpired() {
        return TIME - last > 1;
    }

    protected boolean isExpired(int expiration) {
        return TIME - last > expiration;
    }

    protected synchronized void add(int value, int population) {
        xiSum -= xiSum / population;
        xi2Sum -= xi2Sum / population;
        xiSum += value;
        xi2Sum += value * value;
        last = TIME;
        if (flag instanceof Integer) {
            int count = (Integer) flag;
            flag = count + 1;
        }
    }

    protected synchronized float[] getXiSum() {
        float[] xiResult = new float[2];
        xiResult[0] = xiSum;
        xiResult[1] = xi2Sum;
        return xiResult;
    }
    
    protected float[] getAvgStd(int population) {
        float[] xisArray = getXiSum();
        float xis = xisArray[0];
        float xi2s = xisArray[1];
        float avg = xis / population;
        float std = xi2s;
        std -= 2 * avg * xis;
        std += population * avg * avg;
        std /= population - 1;
        float[] result = {avg, std};
        return result;
    }
    
    public boolean isInconclusive() {
        byte[] extremes = getExtremes();
        return extremes[0] < 0 && extremes[1] > 0;
    }

    public synchronized byte[] getExtremes() {
        byte[] extremes = new byte[2];
        extremes[0] = minimum;
        extremes[1] = maximum;
        return extremes;
    }
    
    protected synchronized Object getFlagObject() {
        return flag;
    }
    
    public synchronized boolean hasFlag() {
        return flag instanceof Flag;
    }

    protected synchronized Flag getFlag() {
        last = TIME;
        if (flag instanceof Flag) {
            return (Flag) flag;
        } else {
            return null;
        }
    }
    
    protected synchronized Flag getFlag(Flag defaultFlag) {
        last = TIME;
        if (flag instanceof Flag) {
            return (Flag) flag;
        } else if (defaultFlag == null) {
            return null;
        } else {
            switch (defaultFlag) {
                case ACCEPTABLE:
                    return Flag.ACCEPTABLE;
                case UNACCEPTABLE:
                    return Flag.UNACCEPTABLE;
                case DESIRABLE:
                    if (maximum < 2) {
                        return Flag.ACCEPTABLE;
                    } else if (minimum < -1) {
                        return Flag.ACCEPTABLE;
                    } else {
                        return Flag.DESIRABLE;
                    }
                case UNDESIRABLE:
                    if (minimum > -2) {
                        return Flag.UNACCEPTABLE;
                    } else if (maximum > 1) {
                        return Flag.UNACCEPTABLE;
                    } else {
                        return Flag.UNDESIRABLE;
                    }
                case BENEFICIAL:
                    if (maximum < 2) {
                        return Flag.ACCEPTABLE;
                    } else if (minimum < -1) {
                        return Flag.ACCEPTABLE;
                    } else if (maximum < 4) {
                        return Flag.DESIRABLE;
                    } else if (minimum < 0) {
                        return Flag.DESIRABLE;
                    } else {
                        return Flag.BENEFICIAL;
                    }
                case HARMFUL:
                    if (minimum > -2) {
                        return Flag.UNACCEPTABLE;
                    } else if (maximum > 1) {
                        return Flag.UNACCEPTABLE;
                    } else if (minimum > -4) {
                        return Flag.UNDESIRABLE;
                    } else if (maximum > 0) {
                        return Flag.UNDESIRABLE;
                    } else {
                        return Flag.HARMFUL;
                    }
                default:
                    return defaultFlag;
            }
        }
    }

    protected synchronized Flag refreshFlag(
            int population, boolean reserved
    ) {
        float[] avgStd = getAvgStd(population);
        float avg = avgStd[0];
        float std = avgStd[1];
        float minStd = avg - 2 * std;
        float maxStd = avg + 2 * std;
        this.minimum = (byte) Math.round(minStd);
        this.maximum = (byte) Math.round(maxStd);
        if (flag instanceof Flag) {
            switch ((Flag) flag) {
                case ACCEPTABLE:
                    if (minStd > 1.5f) {
                        flag = Flag.DESIRABLE;
                        return Flag.DESIRABLE;
                    } else if (maxStd < -1.0f) {
                        flag = Flag.UNDESIRABLE;
                        return Flag.UNDESIRABLE;
                    } else {
                        return Flag.ACCEPTABLE;
                    }
                case UNACCEPTABLE:
                    if (maxStd < -1.5f) {
                        flag = Flag.UNDESIRABLE;
                        return Flag.UNDESIRABLE;
                    } else if (minStd > 1.0f) {
                        flag = Flag.DESIRABLE;
                        return Flag.DESIRABLE;
                    } else {
                        return Flag.UNACCEPTABLE;
                    }
                case DESIRABLE:
                    if (maxStd < 1.0f) {
                        flag = Flag.ACCEPTABLE;
                        return Flag.ACCEPTABLE;
                    } else if (minStd < -2.0f) {
                        flag = Flag.ACCEPTABLE;
                        return Flag.ACCEPTABLE;
                    } else if (reserved) {
                        return Flag.DESIRABLE;
                    } else if (minStd > 3.0f) {
                        flag = Flag.BENEFICIAL;
                        return Flag.BENEFICIAL;
                    } else {
                        return Flag.DESIRABLE;
                    }
                case UNDESIRABLE:
                    if (minStd > -1.0f) {
                        flag = Flag.UNACCEPTABLE;
                        return Flag.UNACCEPTABLE;
                    } else if (maxStd > 2.0f) {
                        flag = Flag.UNACCEPTABLE;
                        return Flag.UNACCEPTABLE;
                    } else if (reserved) {
                        return Flag.UNDESIRABLE;
                    } else if (maxStd < -3.0f) {
                        flag = Flag.HARMFUL;
                        return Flag.HARMFUL;
                    } else {
                        return Flag.UNDESIRABLE;
                    }
                case BENEFICIAL:
                    if (reserved) {
                        flag = Flag.DESIRABLE;
                        return Flag.DESIRABLE;
                    } else if (maxStd < 3.0f) {
                        flag = Flag.DESIRABLE;
                        return Flag.DESIRABLE;
                    } else if (minStd < -1.0f) {
                        flag = Flag.DESIRABLE;
                        return Flag.DESIRABLE;
                    } else {
                        return Flag.BENEFICIAL;
                    }
                case HARMFUL:
                    if (reserved) {
                        flag = Flag.UNDESIRABLE;
                        return Flag.UNDESIRABLE;
                    } else if (minStd > -3.0f) {
                        flag = Flag.UNDESIRABLE;
                        return Flag.UNDESIRABLE;
                    } else if (maxStd > 1.0f) {
                        flag = Flag.UNDESIRABLE;
                        return Flag.UNDESIRABLE;
                    } else {
                        return Flag.HARMFUL;
                    }
                default:
                    return (Flag) flag;
            }
        } else if (flag instanceof Integer) {
            int count = (Integer) flag;
            if (count < population) {
                return null;
            } else if (avg < 0.0f) {
                switch (Math.round(avg)) {
                    case 0: case -1:
                        flag = Flag.UNACCEPTABLE;
                        return Flag.UNACCEPTABLE;
                    case -2: case -3:
                        flag = Flag.UNDESIRABLE;
                        return Flag.UNDESIRABLE;
                    default:
                        flag = Flag.HARMFUL;
                        return Flag.HARMFUL;
                }
            } else {
                switch (Math.round(avg)) {
                    case 0: case 1:
                        flag = Flag.ACCEPTABLE;
                        return Flag.ACCEPTABLE;
                    case 2: case 3:
                        flag = Flag.DESIRABLE;
                        return Flag.DESIRABLE;
                    default:
                        flag = Flag.BENEFICIAL;
                        return Flag.BENEFICIAL;
                }
            }
        } else {
            flag = ZERO;
            return null;
        }
    }
    
    public static boolean isBeneficial(
            String ip, String fqdn
    ) {
        if (fqdn != null) {
            Flag flag = FQDN.getFlag(fqdn);
            if (flag == BENEFICIAL) {
                return true;
            } else if (flag == UNDESIRABLE) {
                return false;
            } else if (flag == HARMFUL) {
                return false;
            }
        }
        Flag flag = CIDR.getFlag(ip);
        return flag == BENEFICIAL;
    }
    
    public static boolean isBeneficial(
            String ip, String fqdn, String helo,
            String sender, Qualifier qualifier,
            String from, TreeSet<String> signerSet
    ) {
        if (from != null && signerSet != null) {
            Flag flag = DKIM.getFlag(from, signerSet);
            if (flag == Flag.UNDESIRABLE) {
                return false;
            } else if (flag == Flag.HARMFUL) {
                return false;
            }
        }
        if (sender != null && qualifier != null) {
            Flag flag = net.spfbl.data.SPF.getFlag(sender, qualifier);
            if (flag == Flag.BENEFICIAL) {
                return true;
            } else if (flag == Flag.UNDESIRABLE) {
                return false;
            } else if (flag == Flag.HARMFUL) {
                return false;
            }
        }
        if (fqdn != null) {
            Flag flag = FQDN.getFlag(fqdn);
            if (flag == Flag.BENEFICIAL) {
                return true;
            } else if (flag == Flag.UNDESIRABLE) {
                return false;
            } else if (flag == Flag.HARMFUL) {
                return false;
            }
        } else if (helo != null) {
            Flag flag = Generic.getFlag(helo);
            if (flag == Flag.BENEFICIAL) {
                return true;
            } else if (flag == Flag.UNDESIRABLE) {
                return false;
            } else if (flag == Flag.HARMFUL) {
                return false;
            }
        }
        Flag flag = CIDR.getFlag(ip);
        return flag == Flag.BENEFICIAL;
    }
    
    public static boolean isDesirable(
            String ip, String fqdn, String helo,
            String sender, Qualifier qualifier,
            String from, TreeSet<String> signerSet
    ) {
        if (signerSet != null) {
            Flag flag = DKIM.getFlag(from, signerSet);
            if (flag == Flag.UNDESIRABLE) {
                return false;
            } else if (flag == Flag.HARMFUL) {
                return false;
            }
        }
        if (sender != null && qualifier != null) {
            Flag flag = net.spfbl.data.SPF.getFlag(sender, qualifier);
            if (flag == Flag.BENEFICIAL) {
                return true;
            } else if (flag == Flag.DESIRABLE) {
                return true;
            } else if (flag == Flag.UNDESIRABLE) {
                return false;
            } else if (flag == Flag.HARMFUL) {
                return false;
            }
        }
        if (fqdn != null) {
            Flag flag = FQDN.getFlag(fqdn);
            if (flag == Flag.BENEFICIAL) {
                return true;
            } else if (flag == Flag.DESIRABLE) {
                return true;
            } else if (flag == Flag.UNDESIRABLE) {
                return false;
            } else if (flag == Flag.HARMFUL) {
                return false;
            }
        } else if (helo != null) {
            Flag flag = Generic.getFlag(helo);
            if (flag == Flag.BENEFICIAL) {
                return true;
            } else if (flag == Flag.DESIRABLE) {
                return true;
            } else if (flag == Flag.UNDESIRABLE) {
                return false;
            } else if (flag == Flag.HARMFUL) {
                return false;
            }
        }
        Flag flag = CIDR.getFlag(ip);
        if (flag == Flag.BENEFICIAL) {
            return true;
        } else if (flag == Flag.DESIRABLE) {
            return true;
        } else {
            return false;
        }
    }
    
    public static boolean isDesirable(String token) {
        if (token == null) {
            return false;
        } else if (isValidIP(token)) {
            Flag flag = CIDR.getFlag(token);
            if (flag == Flag.BENEFICIAL) {
                return true;
            } else if (flag == Flag.DESIRABLE) {
                return true;
            } else {
                return false;
            }
        } else if (isHostname(token)) {
            Flag flag = FQDN.getFlag(token);
            if (flag == Flag.BENEFICIAL) {
                return true;
            } else if (flag == Flag.DESIRABLE) {
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }
    
    public static boolean isHarmful(
            String ip, String fqdn
    ) {
        String sender = null;
        Qualifier qualifier = null;
        return isHarmful(ip, fqdn, null, sender, qualifier, null, null);
    }
    
    public static boolean isHarmful(
            String ip, String fqdn, String helo,
            String sender, Qualifier qualifier,
            String from, TreeSet<String> signerSet
    ) {
        if (from != null && signerSet != null) {
            Flag flag = DKIM.getFlag(from, signerSet);
            if (flag == Flag.HARMFUL) {
                return true;
            }
        }
        if (sender != null && qualifier != null) {
            Flag flag = net.spfbl.data.SPF.getFlag(sender, qualifier);
            if (flag == Flag.BENEFICIAL) {
                return false;
            } else if (flag == Flag.DESIRABLE) {
                return false;
            } else if (flag == Flag.HARMFUL) {
                return true;
            }
        }
        if (fqdn != null) {
            Flag flag = FQDN.getFlag(fqdn);
            if (flag == Flag.BENEFICIAL) {
                return false;
            } else if (flag == Flag.DESIRABLE) {
                return false;
            } else if (flag == Flag.HARMFUL) {
                return true;
            }
        } else if (helo != null) {
            Flag flag = Generic.getFlag(helo);
            if (flag == Flag.BENEFICIAL) {
                return false;
            } else if (flag == Flag.DESIRABLE) {
                return false;
            } else if (flag == Flag.HARMFUL) {
                return true;
            }
        }
        Flag flag = CIDR.getFlag(ip);
        return flag == Flag.HARMFUL;
    }
    
    public static boolean isHarmful(
            String ip, String fqdn, String helo,
            String sender, String result
    ) {
        if (sender != null && result != null) {
            Flag flag = net.spfbl.data.SPF.getFlag(sender, result);
            if (flag == Flag.BENEFICIAL) {
                return false;
            } else if (flag == Flag.DESIRABLE) {
                return false;
            } else if (flag == Flag.HARMFUL) {
                return true;
            }
        }
        if (fqdn != null) {
            Flag flag = FQDN.getFlag(fqdn);
            if (flag == Flag.BENEFICIAL) {
                return false;
            } else if (flag == Flag.DESIRABLE) {
                return false;
            } else if (flag == Flag.HARMFUL) {
                return true;
            }
        } else if (helo != null) {
            Flag flag = Generic.getFlag(helo);
            if (flag == Flag.BENEFICIAL) {
                return false;
            } else if (flag == Flag.DESIRABLE) {
                return false;
            } else if (flag == Flag.HARMFUL) {
                return true;
            }
        }
        Flag flag = CIDR.getFlag(ip);
        return flag == Flag.HARMFUL;
    }
    
    public static boolean isHarmful(
            String ip, String fqdn, String helo,
            String sender, Qualifier qualifier
    ) {
        if (sender != null && qualifier != null) {
            Flag flag = net.spfbl.data.SPF.getFlag(sender, qualifier);
            if (flag == Flag.BENEFICIAL) {
                return false;
            } else if (flag == Flag.DESIRABLE) {
                return false;
            } else if (flag == Flag.HARMFUL) {
                return true;
            }
        }
        if (fqdn != null) {
            Flag flag = FQDN.getFlag(fqdn);
            if (flag == Flag.BENEFICIAL) {
                return false;
            } else if (flag == Flag.DESIRABLE) {
                return false;
            } else if (flag == Flag.HARMFUL) {
                return true;
            }
        } else if (helo != null) {
            Flag flag = Generic.getFlag(helo);
            if (flag == Flag.BENEFICIAL) {
                return false;
            } else if (flag == Flag.DESIRABLE) {
                return false;
            } else if (flag == Flag.HARMFUL) {
                return true;
            }
        }
        Flag flag = CIDR.getFlag(ip);
        return flag == Flag.HARMFUL;
    }
    
    public static boolean isExtreme(
            String ip, String fqdn, String helo,
            String sender, Qualifier qualifier
    ) {
        Flag flagSender = net.spfbl.data.SPF.getFlag(sender, qualifier);
        if (flagSender == Flag.BENEFICIAL) {
            return true;
        } else if (flagSender == Flag.HARMFUL) {
            return true;
        } else {
            Flag flagServer = null;
            if (fqdn != null) {
                flagServer = FQDN.getFlag(fqdn);
            } else if (helo != null) {
                flagServer = Generic.getFlag(helo);
            }
            if (flagServer != Flag.BENEFICIAL && flagServer != Flag.HARMFUL) {
                flagServer = CIDR.getFlag(ip);
            }
            if (flagServer == Flag.BENEFICIAL) {
                return flagSender != Flag.UNDESIRABLE;
            } else if (flagServer == Flag.HARMFUL) {
                return flagSender != Flag.DESIRABLE;
            } else {
                return false;
            }
        }
    }
    
    public static boolean isUndesirable(
            String ip, String fqdn
    ) {
        String sender = null;
        Qualifier qualifier = null;
        return isUndesirable(ip, fqdn, null, sender, qualifier, null, null);
    }
    
    public static boolean isUndesirable(
            String ip, String fqdn, String helo,
            String sender, Qualifier qualifier,
            String from, TreeSet<String> signerSet
    ) {
        if (from != null && signerSet != null) {
            Flag flag = DKIM.getFlag(from, signerSet);
            if (flag == Flag.HARMFUL) {
                return true;
            } else if (flag == Flag.UNDESIRABLE) {
                return true;
            }
        }
        if (sender != null && qualifier != null) {
            Flag flag = net.spfbl.data.SPF.getFlag(sender, qualifier);
            if (flag == Flag.BENEFICIAL) {
                return false;
            } else if (flag == Flag.DESIRABLE) {
                return false;
            } else if (flag == Flag.HARMFUL) {
                return true;
            } else if (flag == Flag.UNDESIRABLE) {
                return true;
            }
        }
        if (fqdn != null) {
            Flag flag = FQDN.getFlag(fqdn);
            if (flag == Flag.BENEFICIAL) {
                return false;
            } else if (flag == Flag.DESIRABLE) {
                return false;
            } else if (flag == Flag.HARMFUL) {
                return true;
            } else if (flag == Flag.UNDESIRABLE) {
                return true;
            }
        } else if (helo != null) {
            Flag flag = Generic.getFlag(helo);
            if (flag == Flag.BENEFICIAL) {
                return false;
            } else if (flag == Flag.DESIRABLE) {
                return false;
            } else if (flag == Flag.HARMFUL) {
                return true;
            } else if (flag == Flag.UNDESIRABLE) {
                return true;
            }
        }
        Flag flag = CIDR.getFlag(ip);
        if (flag == Flag.HARMFUL) {
            return true;
        } else if (flag == Flag.UNDESIRABLE) {
            return true;
        } else {
            return false;
        }
    }
    
    public static Flag getEnvelopeFlag(
            String ip, String fqdn, String helo,
            String sender, String result,
            User user, String recipient
    ) {
        Flag cidrFlag = CIDR.getFlag(ip);
        Flag heloFlag = Generic.getFlag(helo);
        Flag fqdnFlag = FQDN.getFlag(fqdn);
        Flag abuseFlag = Abuse.getFlag(ip, fqdn);
        Flag senderFlag = SPF.getFlag(sender, result);
        Flag recipientFlag = Recipient.getFlag(user, recipient);
        return NeuralNetwork.getFlagEnvelope(
                cidrFlag, heloFlag, fqdnFlag,
                abuseFlag, senderFlag, recipientFlag
        );
    }
    
    public static boolean isUndesirable(
            String ip, String fqdn, String helo,
            String sender, String result,
            User user, String recipient
    ) {
        Flag envelopeFlag = getEnvelopeFlag(
                ip, fqdn, helo,
                sender, result,
                user, recipient
        );
        if (envelopeFlag == HARMFUL) {
            return true;
        } else if (envelopeFlag == UNDESIRABLE) {
            return true;
        } else {
            return false;
        }
    }
    
    public static boolean isDesirable(
            String ip, String fqdn, String helo,
            String sender, String result
    ) {
        if (sender != null && result != null) {
            Flag flag = net.spfbl.data.SPF.getFlag(sender, result);
            if (flag == Flag.BENEFICIAL) {
                return true;
            } else if (flag == Flag.DESIRABLE) {
                return true;
            } else if (flag == Flag.HARMFUL) {
                return false;
            } else if (flag == Flag.UNDESIRABLE) {
                return false;
            }
        }
        if (fqdn != null) {
            Flag flag = FQDN.getFlag(fqdn);
            if (flag == Flag.BENEFICIAL) {
                return true;
            } else if (flag == Flag.DESIRABLE) {
                return true;
            } else if (flag == Flag.HARMFUL) {
                return false;
            } else if (flag == Flag.UNDESIRABLE) {
                return false;
            }
        } else if (helo != null) {
            Flag flag = Generic.getFlag(helo);
            if (flag == Flag.BENEFICIAL) {
                return true;
            } else if (flag == Flag.DESIRABLE) {
                return true;
            } else if (flag == Flag.HARMFUL) {
                return false;
            } else if (flag == Flag.UNDESIRABLE) {
                return false;
            }
        }
        Flag flag = CIDR.getFlag(ip);
        if (flag == Flag.BENEFICIAL) {
            return true;
        } else if (flag == Flag.DESIRABLE) {
            return true;
        } else {
            return false;
        }
    }
    
    public static boolean isDesirable(
            String ip, String fqdn
    ) {
        if (fqdn != null) {
            Flag flag = FQDN.getFlag(fqdn);
            if (flag == Flag.BENEFICIAL) {
                return true;
            } else if (flag == Flag.DESIRABLE) {
                return true;
            } else if (flag == Flag.HARMFUL) {
                return false;
            } else if (flag == Flag.UNDESIRABLE) {
                return false;
            }
        }
        Flag flag = CIDR.getFlag(ip);
        if (flag == Flag.BENEFICIAL) {
            return true;
        } else if (flag == Flag.DESIRABLE) {
            return true;
        } else {
            return false;
        }
    }
    
    public static void addHarmful(
            Client client, User user,
            String abuse, String ip, String fqdn, String helo,
            String sender, Qualifier qualifier, String recipient
    ) {
        Abuse.addHarmful(abuse);
        CIDR.addHarmful(ip);
        SPF.addHarmful(sender, qualifier);
        Generic.addHarmful(helo);
        FQDN.addHarmful(fqdn);
        Recipient.addHarmful(client, user, recipient);
    }
    
    public static void addHarmful(
            Client client, User user,
            String ip, String fqdn, String helo,
            String sender, String result, String recipient
    ) {
        String abuse = Abuse.getEmail(ip, fqdn, sender, result);
        Abuse.addHarmful(abuse);
        CIDR.addHarmful(ip);
        SPF.addHarmful(sender, result);
        Generic.addHarmful(helo);
        FQDN.addHarmful(fqdn);
        Recipient.addHarmful(client, user, recipient);
    }
    
    public static void addUndesirable(
            Client client, User user,
            String abuse, String ip, String fqdn, String helo,
            String sender, Qualifier qualifier, String recipient
    ) {
        Abuse.addUndesirable(abuse);
        CIDR.addUndesirable(ip);
        SPF.addUndesirable(sender, qualifier);
        Generic.addUndesirable(helo);
        FQDN.addUndesirable(fqdn);
        Recipient.addUndesirable(client, user, recipient);
    }
    
    public static void addUndesirable(
            Client client, User user,
            String ip, String fqdn, String helo,
            String sender, String result, String recipient
    ) {
        String abuse = Abuse.getEmail(ip, fqdn, sender, result);
        Abuse.addUndesirable(abuse);
        CIDR.addUndesirable(ip);
        SPF.addUndesirable(sender, result);
        Generic.addUndesirable(helo);
        FQDN.addUndesirable(fqdn);
        Recipient.addUndesirable(client, user, recipient);
    }
    
    public static void addUnacceptable(
            Client client, User user,
            String abuse, String ip, String fqdn, String helo,
            String sender, Qualifier qualifier, String recipient
    ) {
        Abuse.addUnacceptable(abuse);
        CIDR.addUnacceptable(ip);
        SPF.addUnacceptable(sender, qualifier);
        Generic.addUnacceptable(helo);
        FQDN.addUnacceptable(fqdn);
        Recipient.addUnacceptable(client, user, recipient);
    }
    
    public static void addUnacceptable(
            Client client, User user,
            String ip, String fqdn, String helo,
            String sender, String result, String recipient
    ) {
        String abuse = Abuse.getEmail(ip, fqdn, sender, result);
        Abuse.addUnacceptable(abuse);
        CIDR.addUnacceptable(ip);
        SPF.addUnacceptable(sender, result);
        Generic.addUnacceptable(helo);
        FQDN.addUnacceptable(fqdn);
        Recipient.addUnacceptable(client, user, recipient);
    }
    
    public static void addAcceptable(
            Client client, User user,
            String abuse, String ip, String fqdn, String helo,
            String sender, Qualifier qualifier, String recipient
    ) {
        Abuse.addAcceptable(abuse);
        CIDR.addAcceptable(ip);
        SPF.addAcceptable(sender, qualifier);
        Generic.addAcceptable(helo);
        FQDN.addAcceptable(fqdn);
        Recipient.addAcceptable(client, user, recipient);
    }
    
    public static void addAcceptable(
            Client client, User user,
            String ip, String fqdn, String helo,
            String sender, String result, String recipient
    ) {
        String abuse = Abuse.getEmail(ip, fqdn, sender, result);
        Abuse.addAcceptable(abuse);
        CIDR.addAcceptable(ip);
        SPF.addAcceptable(sender, result);
        Generic.addAcceptable(helo);
        FQDN.addAcceptable(fqdn);
        Recipient.addAcceptable(client, user, recipient);
    }
    
    public static void addDesirable(
            Client client, User user,
            String abuse, String ip, String fqdn, String helo,
            String sender, Qualifier qualifier, String recipient
    ) {
        Abuse.addDesirable(abuse);
        CIDR.addDesirable(ip);
        SPF.addDesirable(sender, qualifier);
        Generic.addDesirable(helo);
        FQDN.addDesirable(fqdn);
        Recipient.addDesirable(client, user, recipient);
    }
    
    public static void addDesirable(
            Client client, User user,
            String ip, String fqdn, String helo,
            String sender, String result, String recipient
    ) {
        String abuse = Abuse.getEmail(ip, fqdn, sender, result);
        Abuse.addDesirable(abuse);
        CIDR.addDesirable(ip);
        
        SPF.addDesirable(sender, result);
        Generic.addDesirable(helo);
        FQDN.addDesirable(fqdn);
        Recipient.addDesirable(client, user, recipient);
    }
    
    public static void addBeneficial(
            Client client, User user,
            String abuse, String ip, String fqdn, String helo,
            String sender, Qualifier qualifier, String recipient
    ) {
        Abuse.addBeneficial(abuse);
        CIDR.addBeneficial(ip);
        SPF.addBeneficial(sender, qualifier);
        Generic.addBeneficial(helo);
        FQDN.addBeneficial(fqdn);
        Recipient.addBeneficial(client, user, recipient);
    }
    
    public static void addBeneficial(
            Client client, User user,
            String ip, String fqdn, String helo,
            String sender, String result, String recipient
    ) {
        String abuse = Abuse.getEmail(ip, fqdn, sender, result);
        Abuse.addBeneficial(abuse);
        CIDR.addBeneficial(ip);
        SPF.addBeneficial(sender, result);
        Generic.addBeneficial(helo);
        FQDN.addBeneficial(fqdn);
        Recipient.addBeneficial(client, user, recipient);
    }
}