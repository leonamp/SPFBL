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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.util.PriorityQueue;
import java.util.Set;
import org.apache.commons.lang3.SerializationUtils;

/**
 * Algoritmo de Hullman para compressão de texto.
 *
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Huffman implements Comparable<Huffman>, Serializable {

    private static final long serialVersionUID = 1L;

    private final char character;
    private final int frequency;
    private final Huffman left, right;
    
    private Huffman(char character, int frequency, Huffman left, Huffman right) {
        this.character = character;
        this.frequency = frequency;
        this.left = left;
        this.right = right;
    }

    private boolean isLeaf() {
        assert ((left == null) && (right == null)) || ((left != null) && (right != null));
        return (left == null) && (right == null);
    }

    @Override
    public int compareTo(Huffman other) {
        return this.frequency - other.frequency;
    }
    
    public static void main(String[] args) throws Exception {
        try {
            Huffman huffman = load();
            int[] frequency = new int[256];
            frequency['+']++;
            File file = new File("C:\\Users\\Leandro\\Desktop\\amostra.txt");
            BufferedReader reader = new BufferedReader(new FileReader(file));
            String line;
            
            while ((line = reader.readLine()) != null) {
                String query = null;
                byte[] byteArray = null;
                try {
                    byteArray = Server.decryptToByteArrayURLSafe(line);
                } catch (Exception ex) {
                    try {
                        byteArray = Server.decryptToByteArray(line);
                    } catch (Exception ex2) {
                        try {
                            query = Server.decrypt(line);
                        } catch (Exception ex3) {
                        }
                    }
                }
                if (byteArray != null) {
                    try {
                        query = huffman.decode(byteArray, 8);
                    } catch (Exception ex) {
                        try {
                            query = huffman.decode(byteArray, 0);
                        } catch (Exception ex2) {
                            query = null;
                        }
                    }
                }
                if (query != null) {
                    System.out.println(query);
                    query += '\0';
                    char[] input = query.toCharArray();
                    for (int i = 0; i < input.length; i++) {
                        frequency[input[i]]++;
                    }
                }
            }
            reader.close();
            huffman = buildTree(frequency);
            FileOutputStream outputStream = new FileOutputStream("C:\\Users\\Leandro\\Desktop\\huffmanplus.obj");
            SerializationUtils.serialize(huffman, outputStream);
            outputStream.close();

//            int[] frequency = new int[256];
//            int count = 0;
//            String line;
//            while ((line = reader.readLine()) != null) {
//                line = " " + line;
//                if (count % 3 == 0) {
//                    line += '\0';
//                }
//                char[] input = line.toCharArray();
//                for (int i = 0; i < input.length; i++) {
//                    frequency[input[i]]++;
//                }
//                count++;
//            }
//            reader.close();
//            huffman = buildTree(frequency);
//            FileOutputStream outputStream = new FileOutputStream("C:\\Users\\Leandro\\Desktop\\huffmanplus.obj");
//            SerializationUtils.serialize(huffman, outputStream);
//            outputStream.close();
        } finally {
            System.exit(0);
        }
    }
    
    public static Huffman loadPlus() {
        try {
            try (InputStream inputStream = Huffman.class.getResourceAsStream("huffmanplus.obj")) {
                return SerializationUtils.deserialize(inputStream);
            }
        } catch (Exception ex) {
            Server.logError(ex);
            System.exit(1);
            return null;
        }
    }
    
    public static Huffman load() {
        try {
            try (InputStream inputStream = Huffman.class.getResourceAsStream("huffman.obj")) {
                return SerializationUtils.deserialize(inputStream);
            }
        } catch (Exception ex) {
            Server.logError(ex);
            System.exit(1);
            return null;
        }
    }
    
    public byte[] encodeByteArray(String text, int deslocamento) throws ProcessException {
        text += '\0';
        char[] input = text.toCharArray();
        String[] st = new String[256];
        buildCode(st, this, "");
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < input.length; i++) {
            String code = st[input[i]];
            if (code == null) {
                throw new ProcessException("ERROR: COMPRESSION");
            } else {
                for (int j = 0; j < code.length(); j++) {
                    if (code.charAt(j) == '0') {
                        builder.append('0');
                    } else if (code.charAt(j) == '1') {
                        builder.append('1');
                    } else {
                        throw new ProcessException("ERROR: COMPRESSION");
                    }
                }
            }
        }
        // Completar o byte final.
        while (builder.length() % 8 > 0) {
            builder.append('0');
        }
        int n = builder.length() / 8;
        byte[] array = new byte[n+deslocamento];
        String code = builder.toString();
        for (int i = 0; i < n; i++) {
            String octet = code.substring(i * 8, i * 8 + 8);
            array[i+deslocamento] = (byte) (Short.parseShort(octet, 2) & 0xFF);
        }
        return array;
    }
    
    /**
     * Constrói uma árvore de Huffman a partir da 
     * otimização de um conjunto de textos.
     * @param textSet o conjunto de textos para otmizar a compressão.
     * @return a árvore de Huffman com a otimização dos textos.
     */
    public static Huffman buildTree(Set<String> textSet) {
        int[] frequency = new int[256];
        for (String text : textSet) {
            text += '\0';
            char[] input = text.toCharArray();
            for (int i = 0; i < input.length; i++) {
                frequency[input[i]]++;
            }
        }
        return buildTree(frequency);
    }

    private static Huffman buildTree(int[] frequency) {
        PriorityQueue<Huffman> queue = new PriorityQueue<Huffman>();
        for (char i = 0; i < 256; i++) {
            if (frequency[i] > 0) {
                queue.add(new Huffman(i, frequency[i], null, null));
            }
        }
        if (queue.size() == 1) {
            if (frequency['\0'] == 0) {
                queue.add(new Huffman('\0', 0, null, null));
            } else {
                queue.add(new Huffman('\1', 0, null, null));
            }
        }
        while (queue.size() > 1) {
            Huffman left = queue.poll();
            Huffman right = queue.poll();
            Huffman parent = new Huffman('\0', left.frequency + right.frequency, left, right);
            queue.add(parent);
        }
        return queue.poll();
    }

    private static void buildCode(String[] st, Huffman node, String text) {
        if (!node.isLeaf()) {
            buildCode(st, node.left, text + '0');
            buildCode(st, node.right, text + '1');
        } else {
            st[node.character] = text;
        }
    }
    
    public String decode(String code) {
        try {
            StringBuilder builder = new StringBuilder();
            char[] array = code.toCharArray();
            int k = 0;
            while (k < array.length) {                
                Huffman node = this;
                while (!node.isLeaf()) {
                    if (array[k++] == '1') {
                        node = node.right;
                    } else {
                        node = node.left;
                    }
                }
                if (node.character == '\0') {
                    // Fim do texto.
                    break;
                } else {
                    builder.append(node.character);
                }
            }
            return builder.toString();
        } catch (Exception ex) {
            return null;
        }
    }
    
    public String decode(byte[] byteArray, int deslocamento) {
        StringBuilder builder = new StringBuilder();
        for (int i = deslocamento; i < byteArray.length; i++) {
            byte octet = byteArray[i];
            int codeInt = octet & 0xFF;
            String code = Integer.toBinaryString(codeInt);
            while (code.length() < 8) {
                code = '0' + code;
            }
            builder.append(code);
        }
        return decode(builder.toString());
    }
}
