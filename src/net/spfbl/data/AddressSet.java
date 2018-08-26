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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedList;
import java.util.StringTokenizer;
import net.spfbl.core.Server;
import net.spfbl.whois.SubnetIPv4;
import net.spfbl.whois.SubnetIPv6;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Data structure for CIDR set using a minimal memory 
 * space and full read and write paralelism operations.
 * 
 * It is a binary tree that each leaf represents a CIDR notation.
 * The leaf level represents the CIDR mask and each above branch of 
 * this leaf represents a bit at CIDR address.
 * 
 * If the leaf is a Integer, it is the time of last querie.
 * This Integer is the first 32 bits of system current time millis at querie.
 * If not queried for a long time, the CIDR is removed for saving long-term memory. 
 * 
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class AddressSet {
    
    private FileStore STORE;
    
    public AddressSet() {
        STORE = null;
    }
    
    public AddressSet(File file) throws IOException {
        load(file);
        STORE = new FileStore(file);
        
    }
    
    public void start(File file) throws IOException {
        load(file);
        STORE = new FileStore(file);
        STORE.start();
    }
    
    public void start() {
        STORE.start();
    }
    
    private File pause() throws IOException {
        if (STORE == null) {
            return null;
        } else {
            return STORE.pause();
        }
    }
    
    private void unpause() throws IOException {
        STORE.unpause();
    }
    
    private void storeChange(String line) {
        if (STORE != null) {
            STORE.append(line);
        }
    }
    
    private Integer TIME = (int) (System.currentTimeMillis() >>> 32);
    
    private Integer getIntegerTime() {
        return TIME;
    }
    
    private void refreshIntegerTime() {
        int time = (int) (System.currentTimeMillis() >>> 32);
        if (TIME < time) {
            TIME = time;
        }
    }
    
    private boolean add4(String cidr, Integer time) {
        Node parent = getRoot4();
        int index = cidr.indexOf('/');
        int maskMax = Integer.parseInt(cidr.substring(index + 1));
        if (maskMax == 0) {
            parent.setLeft(time);
            parent.setRigth(time);
            return true;
        } else {
            LinkedList<Node> stack = new LinkedList();
            stack.push(parent);
            int address = SubnetIPv4.getAddressIP(cidr.substring(0, index));
            Object element;
            for (int mask = 1; mask < maskMax; mask++) {
                if ((address & 0x80000000) == 0) {
                    element = parent.getLeft();
                } else {
                    element = parent.getRigth();
                }
                if (element instanceof Node) {
                    parent = (Node) element;
                } else if (element instanceof Integer) {
                    break;
                } else {
                    Node node = new Node();
                    if ((address & 0x80000000) == 0) {
                        parent.setLeft(node);
                    } else {
                        parent.setRigth(node);
                    }
                    parent = node;
                }
                address <<= 1;
                stack.push(parent);
            }
            if ((address & 0x80000000) == 0) {
                element = parent.setLeft(time);
            } else {
                element = parent.setRigth(time);
            }
            if (element instanceof Integer) {
                return false;
            } else {
                storeChange("ADD4 " + cidr + " " + time);
                while (!stack.isEmpty()) {
                    Node child = parent;
                    Object left = child.getLeft();
                    Object rigth = child.getRigth();
                    if (left instanceof Integer && rigth instanceof Integer) {
                        parent = stack.pop();
                        if (child == parent.getLeft()) {
                            parent.setLeft(time);
                        } else {
                            parent.setRigth(time);
                        }
                    } else {
                        break;
                    }
                }
                return true;
            }
        }
    }
    
    private boolean remove4(String cidr) {
        Node parent = getRoot4();
        int index = cidr.indexOf('/');
        int maskMax = Integer.parseInt(cidr.substring(index + 1));
        if (maskMax == 0) {
            parent.clearLeft();
            parent.clearRigth();
            return true;
        } else {
            LinkedList<Node> stack = new LinkedList();
            stack.push(parent);
            Integer time = getIntegerTime();
            int address = SubnetIPv4.getAddressIP(cidr.substring(0, index));
            Object element;
            for (int mask = 1; mask < maskMax; mask++) {
                if ((address & 0x80000000) == 0) {
                    element = parent.getLeft();
                } else {
                    element = parent.getRigth();
                }
                if (element instanceof Node) {
                    parent = (Node) element;
                } else if (element == null) {
                    break;
                } else {
                    Node node = new Node();
                    node.setLeft(time);
                    node.setRigth(time);
                    if ((address & 0x80000000) == 0) {
                        parent.setLeft(node);
                    } else {
                        parent.setRigth(node);
                    }
                    parent = node;
                }
                address <<= 1;
                stack.push(parent);
            }
            if ((address & 0x80000000) == 0) {
                element = parent.clearLeft();
            } else {
                element = parent.clearRigth();
            }
            if (element == null) {
                return false;
            } else {
                storeChange("DEL4 " + cidr);
                while (!stack.isEmpty()) {
                    Node child = parent;
                    Object left = child.getLeft();
                    Object rigth = child.getRigth();
                    if (left == null && rigth == null) {
                        parent = stack.pop();
                        if (child == parent.getLeft()) {
                            parent.clearLeft();
                        } else {
                            parent.clearRigth();
                        }
                    } else {
                        break;
                    }
                }
                return true;
            }
        }
    }
    
    private boolean contains4(String cidr, Integer time) {
        Node parent = getRoot4();
        int index = cidr.indexOf('/');
        int maskMax = Integer.parseInt(cidr.substring(index + 1));
        if (maskMax == 0) {
            Object left = parent.getLeft();
            Object rigth = parent.getRigth();
            return left instanceof Integer && rigth instanceof Integer;
        } else {
            int address = SubnetIPv4.getAddressIP(cidr.substring(0, index));
            Object element;
            for (int mask = 1; mask < maskMax; mask++) {
                if ((address & 0x80000000) == 0) {
                    element = parent.getLeft();
                } else {
                    element = parent.getRigth();
                }
                if (element instanceof Node) {
                    parent = (Node) element;
                } else {
                    break;
                }
                address <<= 1;
            }
            if ((address & 0x80000000) == 0) {
                element = parent.getLeft();
            } else {
                element = parent.getRigth();
            }
            if (element instanceof Integer) {
                if ((address & 0x80000000) == 0) {
                    parent.setLeft(time);
                } else {
                    parent.setRigth(time);
                }
                return true;
            } else {
                return false;
            }
        }
    }
    
    private String getLegacy4(String cidr, Integer time) {
        Node parent = getRoot4();
        int index = cidr.indexOf('/');
        int maskMax = Integer.parseInt(cidr.substring(index + 1));
        if (maskMax == 0) {
            Object left = parent.getLeft();
            Object rigth = parent.getRigth();
            if (left instanceof Integer && rigth instanceof Integer) {
                return "CIDR=0.0.0.0/0";
            } else {
                return null;
            }
        } else {
            String ip = cidr.substring(0, index);
            int address = SubnetIPv4.getAddressIP(ip);
            Object element;
            byte mask;
            for (mask = 1; mask < maskMax; mask++) {
                if ((address & 0x80000000) == 0) {
                    element = parent.getLeft();
                } else {
                    element = parent.getRigth();
                }
                if (element instanceof Node) {
                    parent = (Node) element;
                } else {
                    break;
                }
                address <<= 1;
            }
            if ((address & 0x80000000) == 0) {
                element = parent.getLeft();
            } else {
                element = parent.getRigth();
            }
            if (element instanceof Integer) {
                if ((address & 0x80000000) == 0) {
                    parent.setLeft(time);
                } else {
                    parent.setRigth(time);
                }
                return "CIDR=" + SubnetIPv4.normalizeCIDRv4(ip + "/" + mask);
            } else {
                return null;
            }
        }
    }
    
    private boolean add6(String cidr, Integer time) {
        Node parent = getRoot6();
        int index = cidr.indexOf('/');
        int maskMax = Integer.parseInt(cidr.substring(index + 1));
        if (maskMax == 0) {
            parent.setLeft(time);
            parent.setRigth(time);
            return true;
        } else {
            LinkedList<Node> stack = new LinkedList();
            stack.push(parent);
            BigInteger address = new BigInteger(SubnetIPv6.splitByte(cidr.substring(0, index)));
            Object element;
            for (int mask = 1; mask < maskMax; mask++) {
                if (address.testBit(127)) {
                    element = parent.getRigth();
                } else {
                    element = parent.getLeft();
                }
                if (element instanceof Node) {
                    parent = (Node) element;
                } else if (element instanceof Integer) {
                    break;
                } else {
                    Node node = new Node();
                    if (address.testBit(127)) {
                        parent.setRigth(node);
                    } else {
                        parent.setLeft(node);
                    }
                    parent = node;
                }
                address = address.shiftLeft(1);
                stack.push(parent);
            }
            if (address.testBit(127)) {
                element = parent.setRigth(time);
            } else {
                element = parent.setLeft(time);
            }
            if (element instanceof Integer) {
                return false;
            } else {
                storeChange("ADD6 " + cidr + " " + time);
                while (!stack.isEmpty()) {
                    Node child = parent;
                    Object left = child.getLeft();
                    Object rigth = child.getRigth();
                    if (left instanceof Integer && rigth instanceof Integer) {
                        parent = stack.pop();
                        if (child == parent.getLeft()) {
                            parent.setLeft(time);
                        } else {
                            parent.setRigth(time);
                        }
                    } else {
                        break;
                    }
                }
                return true;
            }
        }
    }
    
    private boolean remove6(String cidr) {
        Node parent = getRoot6();
        int index = cidr.indexOf('/');
        int maskMax = Integer.parseInt(cidr.substring(index + 1));
        if (maskMax == 0) {
            parent.clearLeft();
            parent.clearRigth();
            return true;
        } else {
            LinkedList<Node> stack = new LinkedList();
            stack.push(parent);
            Integer time = getIntegerTime();
            BigInteger address = new BigInteger(SubnetIPv6.splitByte(cidr.substring(0, index)));
            Object element;
            for (int mask = 1; mask < maskMax; mask++) {
                if (address.testBit(127)) {
                    element = parent.getRigth();
                } else {
                    element = parent.getLeft();
                }
                if (element instanceof Node) {
                    parent = (Node) element;
                } else if (element == null) {
                    break;
                } else {
                    Node node = new Node();
                    node.setLeft(time);
                    node.setRigth(time);
                    if (address.testBit(127)) {
                        parent.setRigth(node);
                    } else {
                        parent.setLeft(node);
                    }
                    parent = node;
                }
                address = address.shiftLeft(1);
                stack.push(parent);
            }
            if (address.testBit(127)) {
                element = parent.clearRigth();
            } else {
                element = parent.clearLeft();
            }
            if (element == null) {
                return false;
            } else {
                storeChange("DEL6 " + cidr);
                while (!stack.isEmpty()) {
                    Node child = parent;
                    Object left = child.getLeft();
                    Object rigth = child.getRigth();
                    if (left == null && rigth == null) {
                        parent = stack.pop();
                        if (child == parent.getLeft()) {
                            parent.clearLeft();
                        } else {
                            parent.clearRigth();
                        }
                    } else {
                        break;
                    }
                }
                return true;
            }
        }
    }
    
    private boolean contains6(String cidr, Integer time) {
        Node parent = getRoot6();
        int index = cidr.indexOf('/');
        int maskMax = Integer.parseInt(cidr.substring(index + 1));
        if (maskMax == 0) {
            Object left = parent.getLeft();
            Object rigth = parent.getRigth();
            return left instanceof Integer && rigth instanceof Integer;
        } else {
            BigInteger address = new BigInteger(SubnetIPv6.splitByte(cidr.substring(0, index)));
            Object element;
            for (int mask = 1; mask < maskMax; mask++) {
                if (address.testBit(127)) {
                    element = parent.getRigth();
                } else {
                    element = parent.getLeft();
                }
                if (element instanceof Node) {
                    parent = (Node) element;
                } else {
                    break;
                }
                address = address.shiftLeft(1);
            }
            if (address.testBit(127)) {
                element = parent.getRigth();
            } else {
                element = parent.getLeft();
            }
            if (element instanceof Integer) {
                if (address.testBit(127)) {
                    parent.setRigth(time);
                } else {
                    parent.setLeft(time);
                }
                return true;
            } else {
                return false;
            }
        }
    }
    
    private String getLegacy6(String cidr, Integer time) {
        Node parent = getRoot6();
        int index = cidr.indexOf('/');
        int maskMax = Integer.parseInt(cidr.substring(index + 1));
        if (maskMax == 0) {
            Object left = parent.getLeft();
            Object rigth = parent.getRigth();
            if (left instanceof Integer && rigth instanceof Integer) {
                return "CIDR=0:0:0:0:0:0:0:0/0";
            } else {
                return null;
            }
        } else {
            String ip = cidr.substring(0, index);
            BigInteger address = new BigInteger(SubnetIPv6.splitByte(ip));
            Object element;
            short mask;
            for (mask = 1; mask < maskMax; mask++) {
                if (address.testBit(127)) {
                    element = parent.getRigth();
                } else {
                    element = parent.getLeft();
                }
                if (element instanceof Node) {
                    parent = (Node) element;
                } else {
                    break;
                }
                address = address.shiftLeft(1);
            }
            if (address.testBit(127)) {
                element = parent.getRigth();
            } else {
                element = parent.getLeft();
            }
            if (element instanceof Integer) {
                if (address.testBit(127)) {
                    parent.setRigth(time);
                } else {
                    parent.setLeft(time);
                }
                return "CIDR=" + SubnetIPv6.normalizeCIDRv6(ip + "/" + mask);
            } else {
                return null;
            }
        }
    }
    
    public void clear() {
        Node root4 = getRoot4();
        Node root6 = getRoot6();
        root4.clearLeft();
        root4.clearRigth();
        root6.clearLeft();
        root6.clearRigth();
    }
    
    public boolean add(String token) {
        if (token == null) {
            return false;
        } else if (SubnetIPv4.isValidIPv4(token)) {
            return add4(token + "/32", getIntegerTime());
        } else if (SubnetIPv4.isValidCIDRv4(token)) {
            return add4(token, getIntegerTime());
        } else if (SubnetIPv6.isValidIPv6(token)) {
            return add6(token + "/128", getIntegerTime());
        } else if (SubnetIPv6.isValidCIDRv6(token)) {
            return add6(token, getIntegerTime());
        } else {
            return false;
        }
    }
    
    public String getLegacy(String token) {
        if (token == null) {
            return null;
        } else if (SubnetIPv4.isValidIPv4(token)) {
            return getLegacy4(token + "/32", getIntegerTime());
        } else if (SubnetIPv4.isValidCIDRv4(token)) {
            return getLegacy4(token, getIntegerTime());
        } else if (SubnetIPv6.isValidIPv6(token)) {
            return getLegacy6(token + "/128", getIntegerTime());
        } else if (SubnetIPv6.isValidCIDRv6(token)) {
            return getLegacy6(token, getIntegerTime());
        } else {
            return null;
        }
    }
    
    public boolean remove(String token) {
        if (token == null) {
            return false;
        } else if (SubnetIPv4.isValidIPv4(token)) {
            return remove4(token + "/32");
        } else if (SubnetIPv4.isValidCIDRv4(token)) {
            return remove4(token);
        } else if (SubnetIPv6.isValidIPv6(token)) {
            return remove6(token + "/128");
        } else if (SubnetIPv6.isValidCIDRv6(token)) {
            return remove6(token);
        } else {
            return false;
        }
    }
    
    public boolean contains(String token) {
        if (token == null) {
            return false;
        } else if (SubnetIPv4.isValidIPv4(token)) {
            return contains4(token + "/32", getIntegerTime());
        } else if (SubnetIPv4.isValidCIDRv4(token)) {
            return contains4(token, getIntegerTime());
        } else if (SubnetIPv6.isValidIPv6(token)) {
            return contains6(token + "/128", getIntegerTime());
        } else if (SubnetIPv6.isValidCIDRv6(token)) {
            return contains6(token, getIntegerTime());
        } else {
            return false;
        }
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
//            AddressSet addressSet = new AddressSet();
//            addressSet.add("2001:0db8:85a3:08d2::/24");
//            System.out.println(addressSet.getLegacy("2001:0db8:85a3:08d2::3"));
////            addressSet.add("192.168.0.0/16");
////            System.out.println(addressSet.get("192.168.1.1"));
//            
////            Node root4 = addressSet.getRoot4();
////            System.out.println();
            
            Runtime runtime = Runtime.getRuntime();
            System.out.println(runtime.totalMemory() - runtime.freeMemory());
            File file = new File("C:\\Users\\leandro\\Desktop\\block.cidr.txt");
            AddressSet addressSet = new AddressSet(file);
            addressSet.start();
            System.out.println(runtime.totalMemory() - runtime.freeMemory());
//            for (int count1 = 0; count1 < 256; count1++) {
//                for (int count2 = 0; count2 < 256; count2++) {
//                    addressSet.remove("192.168." + count1 + "." + count2);
//                }
//                addressSet.add("192.168." + count1 + ".0/24");
//            }
//            addressSet.store();
//            addressSet.write4(new PrintWriter(System.out));
            Thread.sleep(1000);
        } catch (Exception ex) {
            ex.printStackTrace();
        } finally {
            System.exit(0);
        }
    }
    
    private void load(File file) {
        long time = System.currentTimeMillis();
        if (file != null && file.exists()) {
            Integer timeInt = getIntegerTime();
            TreeMap<Integer,Integer> timeMap = new TreeMap<>();
            timeMap.put(timeInt, timeInt);
            String token;
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                while ((token = reader.readLine()) != null) {
                    StringTokenizer tokenizer = new StringTokenizer(token, " ");
                    token = tokenizer.nextToken();
                    if (token.equals("ADD4")) {
                        String cidr = tokenizer.nextToken();
                        String changedTime = tokenizer.nextToken();
                        int timeInt4 = Integer.parseInt(changedTime);
                        if ((timeInt = timeMap.get(timeInt4)) == null) {
                            timeMap.put(timeInt4, timeInt4);
                        }
                        add4(cidr, timeInt);
                    } else if (token.equals("ADD6")) {
                        String cidr = tokenizer.nextToken();
                        String changedTime = tokenizer.nextToken();
                        int timeInt6 = Integer.parseInt(changedTime);
                        if ((timeInt = timeMap.get(timeInt6)) == null) {
                            timeMap.put(timeInt6, timeInt6);
                        }
                        add6(cidr, timeInt);
                    } else if (token.equals("DEL4")) {
                        String cidr = tokenizer.nextToken();
                        remove4(cidr);
                    } else if (token.equals("DEL6")) {
                        String cidr = tokenizer.nextToken();
                        remove6(cidr);
                    } else if (token.startsWith("CIDR=")) {
                        token = token.substring(5);
                        if (token.contains(":")) {
                            add6(token, getIntegerTime());
                        } else {
                            add4(token, getIntegerTime());
                        }
                    } else if (SubnetIPv4.isValidCIDRv4(token)) {
                        add4(token, getIntegerTime());
                    } else if (SubnetIPv6.isValidCIDRv6(token)) {
                        add6(token, getIntegerTime());
                    }
                }
                Server.logLoad(time, file);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
    }
    
    private final Node ROOT4 = new Node();
    
    private Node getRoot4() {
        return ROOT4;
    }
    
    private final Node ROOT6 = new Node();
    
    private Node getRoot6() {
        return ROOT6;
    }
    
    private class Node {
        
        private Object left = null;
        private Object rigth = null;
        
        private Object clearLeft() {
            Object element = left;
            left = null;
            return element;
        }
        
        private Object clearRigth() {
            Object element = rigth;
            rigth = null;
            return element;
        }
        
        private Object setLeft(Integer time) {
            Object element = left;
            left = time;
            return element;
        }
        
        private Object setRigth(Integer time) {
            Object element = rigth;
            rigth = time;
            return element;
        }
        
        private void setLeft(Node node) {
            left = node;
        }
        
        private void setRigth(Node node) {
            rigth = node;
        }
        
        private Object getLeft() {
            return left;
        }
        
        private Object getRigth() {
            return rigth;
        }
        
        private Object getNormalizedLeft() {
            Object element = left;
            if (element instanceof Node && ((Node)element).isNull()) {
                return left = null;
            } else {
                return element;
            }
        }
        
        private Object getNormalizedRigth() {
            Object element = rigth;
            if (element instanceof Node && ((Node)element).isNull()) {
                return rigth = null;
            } else {
                return element;
            }
        }
        
        private boolean isNull() {
            return left == null && rigth == null;
        }
    }
    
    private static final BigInteger ONE = BigInteger.valueOf(1);
    
    private static String normalizeCIDRv4(int address, byte mask) {
        int octet4 = address & 0xFF;
        address >>>= 8;
        int octet3 = address & 0xFF;
        address >>>= 8;
        int octet2 = address & 0xFF;
        address >>>= 8;
        int octet1 = address & 0xFF;
        return SubnetIPv4.normalizeCIDRv4(octet1 + "." + octet2 + "." + octet3 + "." + octet4 + "/" + mask);
    }
    
    private static String normalizeCIDRv6(BigInteger address, short mask) {
        int p8 = address.intValue() & 0xFFFF;
        address = address.shiftRight(16);
        int p7 = address.intValue() & 0xFFFF;
        address = address.shiftRight(16);
        int p6 = address.intValue() & 0xFFFF;
        address = address.shiftRight(16);
        int p5 = address.intValue() & 0xFFFF;
        address = address.shiftRight(16);
        int p4 = address.intValue() & 0xFFFF;
        address = address.shiftRight(16);
        int p3 = address.intValue() & 0xFFFF;
        address = address.shiftRight(16);
        int p2 = address.intValue() & 0xFFFF;
        address = address.shiftRight(16);
        int p1 = address.intValue() & 0xFFFF;
        return SubnetIPv6.normalizeCIDRv6(
                Integer.toHexString(p1) + ":" +
                Integer.toHexString(p2) + ":" +
                Integer.toHexString(p3) + ":" +
                Integer.toHexString(p4) + ":" +
                Integer.toHexString(p5) + ":" +
                Integer.toHexString(p6) + ":" +
                Integer.toHexString(p7) + ":" +
                Integer.toHexString(p8) + "/" + mask
        );
    }
    
    private void write4(Writer writer) throws IOException {
        LinkedList<Node> stack = new LinkedList();
        stack.push(getRoot4());
        Integer time = getIntegerTime() - 1;
        byte mask = 0;
        int address = 0;
        Node actual;
        Node previuos = null;
        while (!stack.isEmpty()) {
            actual = stack.pop();
            mask++;
            address <<= 1;
            Object left = actual.getNormalizedLeft();
            Object rigth = actual.getNormalizedRigth();
            if (left instanceof Node && rigth instanceof Node) {
                if (rigth == previuos) {
                    mask -= 2;
                    address >>>= 2;
                } else if (left == previuos) {
                    stack.push(actual);
                    stack.push((Node) rigth);
                    address++;
                } else {
                    stack.push(actual);
                    stack.push((Node) left);
                }
            } else if (!(left instanceof Node) && rigth instanceof Node) {
                if (rigth == previuos) {
                    mask -= 2;
                    address >>>= 2;
                } else {
                    if (left instanceof Integer) {
                        if ((Integer) left < time) {
                            actual.clearLeft();
                        } else {
                            writer.write("ADD4 ");
                            writer.write(normalizeCIDRv4(address << (32 - mask), mask));
                            writer.write(' ');
                            writer.write(left.toString());
                            writer.write('\n');
                            writer.flush();
                        }
                    }
                    stack.push(actual);
                    stack.push((Node) rigth);
                    address++;
                }
            } else if (left instanceof Node && !(rigth instanceof Node)) {
                if (left == previuos) {
                    mask -= 2;
                    address >>>= 2;
                } else {
                    if (rigth instanceof Integer) {
                        if ((Integer) rigth < time) {
                            actual.clearRigth();
                        } else {
                            writer.write("ADD4 ");
                            writer.write(normalizeCIDRv4((address + 1) << (32 - mask), mask));
                            writer.write(' ');
                            writer.write(rigth.toString());
                            writer.write('\n');
                            writer.flush();
                        }
                    }
                    stack.push(actual);
                    stack.push((Node) left);
                }
            } else {
                if (left instanceof Integer) {
                    if ((Integer) left < time) {
                        actual.clearLeft();
                    } else {
                        writer.write("ADD4 ");
                        writer.write(normalizeCIDRv4(address << (32 - mask), mask));
                        writer.write(' ');
                        writer.write(left.toString());
                        writer.write('\n');
                        writer.flush();
                    }
                }
                if (rigth instanceof Integer) {
                    if ((Integer) rigth < time) {
                        actual.clearRigth();
                    } else {
                        writer.write("ADD4 ");
                        writer.write(normalizeCIDRv4((address + 1) << (32 - mask), mask));
                        writer.write(' ');
                        writer.write(rigth.toString());
                        writer.write('\n');
                        writer.flush();
                    }
                }
                mask -= 2;
                address >>>= 2;
            }
            previuos = actual;
        }
    }
    
    private void write6(Writer writer) throws IOException {
        LinkedList<Node> stack = new LinkedList();
        stack.push(getRoot6());
        int time = getIntegerTime() - 1;
        short mask = 0;
        BigInteger address = BigInteger.valueOf(0);
        Node actual;
        Node previuos = null;
        while (!stack.isEmpty()) {
            actual = stack.pop();
            mask++;
            address = address.shiftLeft(1);
            Object left = actual.getNormalizedLeft();
            Object rigth = actual.getNormalizedRigth();
            if (left instanceof Node && rigth instanceof Node) {
                if (rigth == previuos) {
                    mask -= 2;
                    address = address.shiftRight(2);
                } else if (left == previuos) {
                    stack.push(actual);
                    stack.push((Node) rigth);
                    address = address.add(ONE);
                } else {
                    stack.push(actual);
                    stack.push((Node) left);
                }
            } else if (!(left instanceof Node) && rigth instanceof Node) {
                if (rigth == previuos) {
                    mask -= 2;
                    address = address.shiftRight(2);
                } else {
                    if (left instanceof Integer) {
                        if ((Integer) left < time) {
                            actual.clearLeft();
                        } else {
                            writer.write("ADD6 ");
                            writer.write(normalizeCIDRv6(address.shiftLeft(128 - mask), mask));
                            writer.write(' ');
                            writer.write(left.toString());
                            writer.write('\n');
                            writer.flush();
                        }
                    }
                    stack.push(actual);
                    stack.push((Node) rigth);
                    address = address.add(ONE);
                }
            } else if (left instanceof Node && !(rigth instanceof Node)) {
                if (left == previuos) {
                    mask -= 2;
                    address = address.shiftRight(2);
                } else {
                    if (rigth instanceof Integer) {
                        if ((Integer) rigth < time) {
                            actual.clearRigth();
                        } else {
                            writer.write("ADD6 ");
                            writer.write(normalizeCIDRv6(address.add(ONE).shiftLeft(128 - mask), mask));
                            writer.write(' ');
                            writer.write(rigth.toString());
                            writer.write('\n');
                            writer.flush();
                        }
                    }
                    stack.push(actual);
                    stack.push((Node) left);
                }
            } else {
                if (left instanceof Integer) {
                    if ((Integer) left < time) {
                        actual.clearLeft();
                    } else {
                        writer.write("ADD6 ");
                        writer.write(normalizeCIDRv6(address.shiftLeft(128 - mask), mask));
                        writer.write(' ');
                        writer.write(left.toString());
                        writer.write('\n');
                        writer.flush();
                    }
                }
                if (rigth instanceof Integer) {
                    if ((Integer) rigth < time) {
                        actual.clearRigth();
                    } else {
                        writer.write("ADD6 ");
                        writer.write(normalizeCIDRv6(address.add(ONE).shiftLeft(128 - mask), mask));
                        writer.write(' ');
                        writer.write(rigth.toString());
                        writer.write('\n');
                        writer.flush();
                    }
                }
                mask -= 2;
                address = address.shiftRight(2);
            }
            previuos = actual;
        }
    }
    
    public void writeLegacy(Writer writer) throws IOException {
        writeLegacy4(writer);
        writeLegacy6(writer);
    }
    
    private void writeLegacy4(Writer writer) throws IOException {
        LinkedList<Node> stack = new LinkedList();
        stack.push(getRoot4());
        int time = getIntegerTime() - 1;
        byte mask = 0;
        int address = 0;
        Node actual;
        Node previuos = null;
        while (!stack.isEmpty()) {
            actual = stack.pop();
            mask++;
            address <<= 1;
            Object left = actual.getNormalizedLeft();
            Object rigth = actual.getNormalizedRigth();
            if (left instanceof Node && rigth instanceof Node) {
                if (rigth == previuos) {
                    mask -= 2;
                    address >>>= 2;
                } else if (left == previuos) {
                    stack.push(actual);
                    stack.push((Node) rigth);
                    address++;
                } else {
                    stack.push(actual);
                    stack.push((Node) left);
                }
            } else if (!(left instanceof Node) && rigth instanceof Node) {
                if (rigth == previuos) {
                    mask -= 2;
                    address >>>= 2;
                } else {
                    if (left instanceof Integer) {
                        if ((Integer) left < time) {
                            actual.clearLeft();
                        } else {
                            writer.write("CIDR=");
                            writer.write(normalizeCIDRv4(address << (32 - mask), mask));
                            writer.write('\n');
                            writer.flush();
                        }
                    }
                    stack.push(actual);
                    stack.push((Node) rigth);
                    address++;
                }
            } else if (left instanceof Node && !(rigth instanceof Node)) {
                if (left == previuos) {
                    mask -= 2;
                    address >>>= 2;
                } else {
                    if (rigth instanceof Integer) {
                        if ((Integer) rigth < time) {
                            actual.clearRigth();
                        } else {
                            writer.write("CIDR=");
                            writer.write(normalizeCIDRv4((address + 1) << (32 - mask), mask));
                            writer.write('\n');
                            writer.flush();
                        }
                    }
                    stack.push(actual);
                    stack.push((Node) left);
                }
            } else {
                if (left instanceof Integer) {
                    if ((Integer) left < time) {
                        actual.clearLeft();
                    } else {
                        writer.write("CIDR=");
                        writer.write(normalizeCIDRv4(address << (32 - mask), mask));
                        writer.write('\n');
                        writer.flush();
                    }
                }
                if (rigth instanceof Integer) {
                    if ((Integer) rigth < time) {
                        actual.clearRigth();
                    } else {
                        writer.write("CIDR=");
                        writer.write(normalizeCIDRv4((address + 1) << (32 - mask), mask));
                        writer.write('\n');
                        writer.flush();
                    }
                }
                mask -= 2;
                address >>>= 2;
            }
            previuos = actual;
        }
    }
    
    private void writeLegacy6(Writer writer) throws IOException {
        LinkedList<Node> stack = new LinkedList();
        stack.push(getRoot6());
        int time = getIntegerTime() - 1;
        short mask = 0;
        BigInteger address = BigInteger.valueOf(0);
        Node actual;
        Node previuos = null;
        while (!stack.isEmpty()) {
            actual = stack.pop();
            mask++;
            address = address.shiftLeft(1);
            Object left = actual.getNormalizedLeft();
            Object rigth = actual.getNormalizedRigth();
            if (left instanceof Node && rigth instanceof Node) {
                if (rigth == previuos) {
                    mask -= 2;
                    address = address.shiftRight(2);
                } else if (left == previuos) {
                    stack.push(actual);
                    stack.push((Node) rigth);
                    address = address.add(ONE);
                } else {
                    stack.push(actual);
                    stack.push((Node) left);
                }
            } else if (!(left instanceof Node) && rigth instanceof Node) {
                if (rigth == previuos) {
                    mask -= 2;
                    address = address.shiftRight(2);
                } else {
                    if (left instanceof Integer) {
                        if ((Integer) left < time) {
                            actual.clearLeft();
                        } else {
                            writer.write("CIDR=");
                            writer.write(normalizeCIDRv6(address.shiftLeft(128 - mask), mask));
                            writer.write('\n');
                            writer.flush();
                        }
                    }
                    stack.push(actual);
                    stack.push((Node) rigth);
                    address = address.add(ONE);
                }
            } else if (left instanceof Node && !(rigth instanceof Node)) {
                if (left == previuos) {
                    mask -= 2;
                    address = address.shiftRight(2);
                } else {
                    if (rigth instanceof Integer) {
                        if ((Integer) rigth < time) {
                            actual.clearRigth();
                        } else {
                            writer.write("CIDR=");
                            writer.write(normalizeCIDRv6(address.add(ONE).shiftLeft(128 - mask), mask));
                            writer.write('\n');
                            writer.flush();
                        }
                    }
                    stack.push(actual);
                    stack.push((Node) left);
                }
            } else {
                if (left instanceof Integer) {
                    if ((Integer) left < time) {
                        actual.clearLeft();
                    } else {
                        writer.write("CIDR=");
                        writer.write(normalizeCIDRv6(address.shiftLeft(128 - mask), mask));
                        writer.write('\n');
                        writer.flush();
                    }
                }
                if (rigth instanceof Integer) {
                    if ((Integer) rigth < time) {
                        actual.clearRigth();
                    } else {
                        writer.write("CIDR=");
                        writer.write(normalizeCIDRv6(address.add(ONE).shiftLeft(128 - mask), mask));
                        writer.write('\n');
                        writer.flush();
                    }
                }
                mask -= 2;
                address = address.shiftRight(2);
            }
            previuos = actual;
        }
    }
    
    public TreeSet<String> getAllLegacy() {
        TreeSet<String> addressSet = new TreeSet<>();
        getAllLegacy4(addressSet);
        getAllLegacy6(addressSet);
        return addressSet;
    }
    
    private void getAllLegacy4(TreeSet<String> addressSet) {
        LinkedList<Node> stack = new LinkedList();
        stack.push(getRoot4());
        int time = getIntegerTime() - 1;
        byte mask = 0;
        int address = 0;
        Node actual;
        Node previuos = null;
        while (!stack.isEmpty()) {
            actual = stack.pop();
            mask++;
            address <<= 1;
            Object left = actual.getNormalizedLeft();
            Object rigth = actual.getNormalizedRigth();
            if (left instanceof Node && rigth instanceof Node) {
                if (rigth == previuos) {
                    mask -= 2;
                    address >>>= 2;
                } else if (left == previuos) {
                    stack.push(actual);
                    stack.push((Node) rigth);
                    address++;
                } else {
                    stack.push(actual);
                    stack.push((Node) left);
                }
            } else if (!(left instanceof Node) && rigth instanceof Node) {
                if (rigth == previuos) {
                    mask -= 2;
                    address >>>= 2;
                } else {
                    if (left instanceof Integer) {
                        if ((Integer) left < time) {
                            actual.clearLeft();
                        } else {
                            addressSet.add("CIDR=" + normalizeCIDRv4(address << (32 - mask), mask));
                        }
                    }
                    stack.push(actual);
                    stack.push((Node) rigth);
                    address++;
                }
            } else if (left instanceof Node && !(rigth instanceof Node)) {
                if (left == previuos) {
                    mask -= 2;
                    address >>>= 2;
                } else {
                    if (rigth instanceof Integer) {
                        if ((Integer) rigth < time) {
                            actual.clearRigth();
                        } else {
                            addressSet.add("CIDR=" + normalizeCIDRv4((address + 1) << (32 - mask), mask));
                        }
                    }
                    stack.push(actual);
                    stack.push((Node) left);
                }
            } else {
                if (left instanceof Integer) {
                    if ((Integer) left < time) {
                        actual.clearLeft();
                    } else {
                        addressSet.add("CIDR=" + normalizeCIDRv4(address << (32 - mask), mask));
                    }
                }
                if (rigth instanceof Integer) {
                    if ((Integer) rigth < time) {
                        actual.clearRigth();
                    } else {
                        addressSet.add("CIDR=" + normalizeCIDRv4((address + 1) << (32 - mask), mask));
                    }
                }
                mask -= 2;
                address >>>= 2;
            }
            previuos = actual;
        }
    }
    
    private void getAllLegacy6(TreeSet<String> addressSet) {
        LinkedList<Node> stack = new LinkedList();
        stack.push(getRoot6());
        int time = getIntegerTime() - 1;
        short mask = 0;
        BigInteger address = BigInteger.valueOf(0);
        Node actual;
        Node previuos = null;
        while (!stack.isEmpty()) {
            actual = stack.pop();
            mask++;
            address = address.shiftLeft(1);
            Object left = actual.getNormalizedLeft();
            Object rigth = actual.getNormalizedRigth();
            if (left instanceof Node && rigth instanceof Node) {
                if (rigth == previuos) {
                    mask -= 2;
                    address = address.shiftRight(2);
                } else if (left == previuos) {
                    stack.push(actual);
                    stack.push((Node) rigth);
                    address = address.add(ONE);
                } else {
                    stack.push(actual);
                    stack.push((Node) left);
                }
            } else if (!(left instanceof Node) && rigth instanceof Node) {
                if (rigth == previuos) {
                    mask -= 2;
                    address = address.shiftRight(2);
                } else {
                    if (left instanceof Integer) {
                        if ((Integer) left < time) {
                            actual.clearLeft();
                        } else {
                            addressSet.add("CIDR=" + normalizeCIDRv6(address.shiftLeft(128 - mask), mask));
                        }
                    }
                    stack.push(actual);
                    stack.push((Node) rigth);
                    address = address.add(ONE);
                }
            } else if (left instanceof Node && !(rigth instanceof Node)) {
                if (left == previuos) {
                    mask -= 2;
                    address = address.shiftRight(2);
                } else {
                    if (rigth instanceof Integer) {
                        if ((Integer) rigth < time) {
                            actual.clearRigth();
                        } else {
                            addressSet.add("CIDR=" + normalizeCIDRv6(address.add(ONE).shiftLeft(128 - mask), mask));
                        }
                    }
                    stack.push(actual);
                    stack.push((Node) left);
                }
            } else {
                if (left instanceof Integer) {
                    if ((Integer) left < time) {
                        actual.clearLeft();
                    } else {
                        addressSet.add("CIDR=" + normalizeCIDRv6(address.shiftLeft(128 - mask), mask));
                    }
                }
                if (rigth instanceof Integer) {
                    if ((Integer) rigth < time) {
                        actual.clearRigth();
                    } else {
                        addressSet.add("CIDR=" + normalizeCIDRv6(address.add(ONE).shiftLeft(128 - mask), mask));
                    }
                }
                mask -= 2;
                address = address.shiftRight(2);
            }
            previuos = actual;
        }
    }
    
    public boolean store() {
        try {
            long time = System.currentTimeMillis();
            File file = pause();
            if (file == null) {
                return false;
            } else {
                try {
                    Path source = file.toPath();
                    Path temp = source.resolveSibling("." + file.getName());
                    try (FileWriter writer = new FileWriter(temp.toFile())) {
                        try {
                            write4(writer);
                        } catch (Exception ex) {
                            Server.logError(ex);
                        }
                        try {
                            write6(writer);
                        } catch (Exception ex) {
                            Server.logError(ex);
                        }
                    }
                    Files.move(temp, source, REPLACE_EXISTING);
                    Server.logStore(time, file);
                    return true;
                } finally {
                    unpause();
                }
            }
        } catch (Exception ex) {
            Server.logError(ex);
            return false;
        } finally {
            refreshIntegerTime();
        }
    }
}
