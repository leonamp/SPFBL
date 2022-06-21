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
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.nio.file.Files;
import java.nio.file.Path;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import java.util.AbstractMap.SimpleEntry;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Locale;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import java.util.regex.Matcher;
import java.util.regex.PatternSyntaxException;
import net.spfbl.core.Core;
import net.spfbl.core.Server;
import net.spfbl.data.Reputation.Flag;
import static net.spfbl.data.Reputation.Flag.ACCEPTABLE;
import static net.spfbl.data.Reputation.Flag.BENEFICIAL;
import static net.spfbl.data.Reputation.Flag.DESIRABLE;
import static net.spfbl.data.Reputation.Flag.HARMFUL;
import static net.spfbl.data.Reputation.Flag.UNACCEPTABLE;
import static net.spfbl.data.Reputation.Flag.UNDESIRABLE;
import static net.spfbl.whois.Domain.normalizeEmail;
import org.apache.commons.text.similarity.LevenshteinDistance;

/**
 * Representa a estrutura de dicionário de palavras.
 *
 * @author Leandro Carlos Rodrigues <leandro@spfbl.net>
 */
public class Dictionary {

    private final TreeMap<String,Integer> WORD_SET = new TreeMap<>();
    private final HashMap<String,String> WORD_MAP = new HashMap<>();
    private final TreeMap<String,Regex<String>> REGEX_MAP = new TreeMap<>();

    private static class Regex<Value> {

        private net.spfbl.core.Regex pattern;
        private Value value;
        private int last;

        private Regex(net.spfbl.core.Regex pattern, Value value) {
            this.pattern = pattern;
            this.value = value;
            this.last = TIME;
        }
        
        private Regex(String regex, Value value, int last) throws PatternSyntaxException {
            this.pattern = new net.spfbl.core.Regex(regex);
            this.value = value;
            this.last = last;
        }

        private Regex(net.spfbl.core.Regex pattern, Value value, int last) {
            this.pattern = pattern;
            this.value = value;
            this.last = last;
        }
        
        public String pattern() {
            return pattern.pattern();
        }

        public boolean matches(String key) {
            if (key == null) {
                return false;
            } else {
                if (pattern.matches(key)) {
                    last = TIME;
                    return true;
                } else {
                    return false;
                }
            }
        }

        public Value getValue() {
            return value;
        }

        public int getLast() {
            return last;
        }

        public boolean isExpired(int time) {
            return TIME - last > time;
        }
    }

    private synchronized TreeSet<String> getKeySet() {
        TreeSet<String> resultSet = new TreeSet<>();
        resultSet.addAll(WORD_MAP.keySet());
        return resultSet;
    }

    private synchronized TreeSet<String> getWordSet() {
        TreeSet<String> resultSet = new TreeSet<>();
        resultSet.addAll(WORD_SET.keySet());
        return resultSet;
    }

    private synchronized String getFirstRegex() {
        if (REGEX_MAP.isEmpty()) {
            return null;
        } else {
            return REGEX_MAP.firstKey();
        }
    }
    
    private TreeSet<String> getRegexSet() {
        TreeSet<String> resultSet = new TreeSet<>();
        resultSet.addAll(REGEX_MAP.keySet());
        return resultSet;
    }

    private String getHigherRegex(String key) {
        return REGEX_MAP.higherKey(key);
    }

    private Regex<String> getRegex(String key) {
        return REGEX_MAP.get(key);
    }

    private synchronized String getFirstWord() {
        if (WORD_SET.isEmpty()) {
            return null;
        } else {
            return WORD_SET.firstKey();
        }
    }

    private String getHigherWord(String word) {
        return WORD_SET.higherKey(word);
    }

    private String getWord(String key) {
        if (key == null) {
            return null;
        } else {
            return WORD_MAP.get(key);
        }
    }
    
    private boolean matches(String key) {
        if (key == null) {
            return false;
        } else {
            String regexKey = getFirstRegex();
            while (regexKey != null) {
                Regex<String> regex = getRegex(regexKey);
                if (regex != null && regex.matches(key)) {
                    return true;
                }
                regexKey = getHigherRegex(regexKey);
            }
            return false;
        }
    }

    private String getMatch(String key) {
        if (key == null) {
            return null;
        } else {
            String regexKey = getFirstRegex();
            while (regexKey != null) {
                Regex<String> regex = getRegex(regexKey);
                if (regex != null && regex.matches(key)) {
                    return regex.getValue();
                }
                regexKey = getHigherRegex(regexKey);
            }
            return null;
        }
    }

    private synchronized boolean addWord(String word) {
        if (word == null) {
            return false;
        } else {
            return WORD_SET.put(word, TIME) == null;
        }
    }

    private synchronized boolean addWord(String word, Integer last) {
        if (word == null) {
            return false;
        } else if (last == null) {
            return false;
        } else {
            return WORD_SET.put(word, last) == null;
        }
    }

    private synchronized boolean putWord(String key, String word) {
        if (key == null) {
            return false;
        } else if (word == null) {
            return false;
        } else {
            String oldValue = WORD_MAP.put(key, word);
            if (oldValue == null) {
                return true;
            } else {
                return !oldValue.equals(word);
            }
        }
    }

    private boolean putRegex(String regex, String word, int last) throws PatternSyntaxException {
        if (regex == null) {
            return false;
        } else if (word == null) {
            return false;
        } else {
            Regex regexObj = new Regex(regex, word, last);
            return putRegex(regex, regexObj);
        }
    }

    private synchronized boolean putRegex(String key, Regex<String> regex) {
        if (key == null) {
            return false;
        } else if (regex == null) {
            return false;
        } else {
            Regex<String> oldValue = REGEX_MAP.put(key, regex);
            if (oldValue == null) {
                return true;
            } else {
                return !oldValue.getValue().equals(regex.getValue());
            }
        }
    }

    private boolean putWord(Locale locale, String key, String word) {
        if (putWord(key, word)) {
            Dictionary.append("PUT "
                    + locale.toLanguageTag()
                    + " " + key + " " + word
            );
            return true;
        } else {
            return false;
        }
    }

    private synchronized boolean isEmpty() {
        return WORD_SET.isEmpty() && WORD_MAP.isEmpty() && REGEX_MAP.isEmpty() && UNDEFINED_MAP.isEmpty();
    }

    private synchronized boolean removeKey(String key) {
        if (key == null) {
            return false;
        } else {
            return WORD_MAP.remove(key) != null;
        }
    }

    private boolean removeRegex(String regex) {
        if (regex == null) {
            return false;
        } else {
            return REGEX_MAP.remove(regex) != null;
        }
    }

    private synchronized boolean removeWord(String word) {
        if (word == null) {
            return false;
        } else {
            return WORD_SET.remove(word) != null;
        }
    }

    private synchronized boolean removeUndefined(String key) {
        if (key == null) {
            return false;
        } else {
            return UNDEFINED_MAP.remove(key) != null;
        }
    }

    private synchronized boolean containsWord(String word) {
        if (word == null) {
            return false;
        } else if (WORD_SET.containsKey(word)) {
            WORD_SET.put(word, TIME);
            return true;
        } else {
            return false;
        }
    }
    
    private synchronized boolean containsKey(String key) {
        if (key == null) {
            return false;
        } else {
            return WORD_MAP.containsKey(key);
        }
    }

    private static Integer TIME = (int) (System.currentTimeMillis() >>> 32);

    public static void refreshTime() {
        int time = (int) (System.currentTimeMillis() >>> 32);
        if (TIME < time) {
            TIME = time;
        }
    }

    private static class Counter {

        private short count = 0;
        private int last = TIME;

        private Counter() {
            this.count = 0;
            this.last = TIME;
        }

        private Counter(short count, int last) {
            this.count = count;
            this.last = last;
        }

        public synchronized boolean increment(int time) {
            last = time;
            if (count == Short.MAX_VALUE) {
                return false;
            } else {
                count++;
                return true;
            }
        }
        
        public synchronized boolean decrement() {
            if (count == 0) {
                return false;
            } else {
                count--;
                return true;
            }
        }

        public boolean isExpired() {
            if (decrement()) {
                return TIME - last > 1;
            } else {
                return true;
            }
        }
    }

    private final HashMap<String,Counter> UNDEFINED_MAP = new HashMap<>();

    private synchronized TreeSet<String> getUndefinedKeySet() {
        TreeSet<String> resultSet = new TreeSet<>();
        resultSet.addAll(UNDEFINED_MAP.keySet());
        return resultSet;
    }

    private synchronized Counter getUndefined(String key) {
        if (key == null) {
            return null;
        } else if (key.isEmpty()) {
            return null;
        } else {
            Counter counter = UNDEFINED_MAP.get(key);
            if (counter == null) {
                counter = new Counter();
                UNDEFINED_MAP.put(key, counter);
            }
            return counter;
        }
    }

    private synchronized void setUndefined(String key, short count, int last) {
        Counter counter = new Counter(count, last);
        UNDEFINED_MAP.put(key, counter);
    }

    private boolean addUndefined(String key, int time) {
        Counter counter = getUndefined(key);
        if (counter == null) {
            return false;
        } else {
            return counter.increment(time);
        }
    }

    private static char normalizeToOcidental(char character) {
        switch (character) {
            case 'Α':
                return 'A';
            case 'А':
                return 'A';
            case 'α':
                return 'a';
            case 'Β':
            case 'В':
            case 'β':
                return 'B';
            case 'Ь':
            case 'Ƅ':
                return 'b';
            case 'с':
                return 'c';
            case 'Ԁ':
                return 'd';
            case 'Ε':
                return 'E';
            case 'ε':
                return 'e';
            case 'ҽ':
                return 'e';
            case 'Ζ':
                return 'Z';
            case 'Η':
                return 'H';
            case 'Θ':
                return 'O';
            case 'θ':
                return 'O';
            case 'о':
                return 'o';
            case 'і':
                return 'i';
            case 'Ι':
                return 'I';
            case 'i':
                return 'i';
            case 'Κ':
                return 'K';
            case 'κ':
                return 'k';
            case 'Μ':
                return 'M';
            case 'м':
                return 'm';
            case 'μ':
                return 'u';
            case 'Ν':
                return 'N';
            case 'ν':
                return 'v';
            case 'ξ':
                return 'E';
            case 'Ο':
                return 'O';
            case 'ο':
                return 'o';
            case 'Ρ':
                return 'P';
            case 'ρ':
                return 'p';
            case 'σ':
                return 'o';
            case 'ς':
                return 'ç';
            case 'Τ':
                return 'T';
            case 'τ':
                return 't';
            case 'Υ':
                return 'Y';
            case 'ᴠ':
                return 'v';
            case 'υ':
                return 'u';
            case 'Χ':
                return 'X';
            case 'χ':
                return 'x';
            case 'ω':
                return 'w';
            default:
                return character;
        }
    }

    private static String normalizeToOcidental(String key) {
        if (key == null) {
            return null;
        } else {
            boolean ocidental = false;
            char[] charArray = key.toCharArray();
            for (int index = 0; index < charArray.length; index++) {
                char character = charArray[index];
                if (character >= 'a' && character <= 'z') {
                    ocidental = true;
                } else if (character >= 'A' && character <= 'Z') {
                    ocidental = true;
                }
                charArray[index] = normalizeToOcidental(character);
            }
            if (ocidental) {
                return new String(charArray);
            } else {
                return key;
            }
        }
    }

    public static String normalizeCharset(String subject) {
        if (subject == null) {
            return null;
        } else {
            subject = normalizeSurrogate(subject);
            String variant = new String(subject.getBytes(ISO_8859_1), UTF_8);
            if (variant.getBytes(UTF_8).length < subject.getBytes(UTF_8).length) {
                subject = variant;
            }
            subject = normalizeSurrogate(subject);
            return subject;
        }
    }
    
    public static String normalizeCharacters(String subject) {
        if (subject == null) {
            return null;
        } else {
            subject = subject.replace('\u0009', ' ');
            subject = subject.replace('\u000B', ' ');
            subject = subject.replace('\u000C', ' ');
            subject = subject.replace('\u0020', ' ');
            subject = subject.replace('\u0085', ' ');
            subject = subject.replace('\u00A0', ' ');
            subject = subject.replace('\u1680', ' ');
            subject = subject.replace('\u180E', ' ');
            subject = subject.replace('\u2000', ' ');
            subject = subject.replace('\u2001', ' ');
            subject = subject.replace('\u2002', ' ');
            subject = subject.replace('\u2003', ' ');
            subject = subject.replace('\u2004', ' ');
            subject = subject.replace('\u2005', ' ');
            subject = subject.replace('\u2006', ' ');
            subject = subject.replace('\u2007', ' ');
            subject = subject.replace('\u2008', ' ');
            subject = subject.replace('\u2009', ' ');
            subject = subject.replace('\u200A', ' ');
            subject = subject.replace('\u200C', ' ');
            subject = subject.replace('\u2028', ' ');
            subject = subject.replace('\u2029', ' ');
            subject = subject.replace('\u202F', ' ');
            subject = subject.replace('\u205F', ' ');
            subject = subject.replace('\u3000', ' ');
            subject = subject.replace('\uFF01', '!');
            subject = subject.replace('\uFF03', '#');
            subject = subject.replace('\uFF08', '(');
            subject = subject.replace('\uFF09', ')');
            subject = subject.replace('\uFF0C', ',');
            subject = subject.replace('\uFF1A', ':');
            subject = subject.replace('\uFF1B', ';');
            subject = subject.replace('\uFF1F', '?');
            subject = subject.replaceAll("[\\s\\t]+", " ");
            subject = subject.replaceAll("[\u2009-\u200F\u2028-\u202e\u206A-\u206F]+", "");
            return subject.trim();
        }
    }

    private static String normalizeSurrogate(String subject) {
        if (subject == null) {
            return null;
        } else {
            StringBuilder builder = new StringBuilder();
            char[] charArray = subject.toCharArray();
            boolean surrogate = false;
            for (int index = 0; index < charArray.length; index++) {
                char character = charArray[index];
                if (character == 0xD835) {
                    surrogate = true;
                } else if (surrogate && character >= 0xDC00 && character <= 0xDEA2) {
                    surrogate = false;
                    // Letter.
                    character -= 0xDC00;
                    character %= 52;
                    if (character < 26) {
                        character += 65;
                    } else {
                        character += 71;
                    }
                    builder.append(character);
                } else if (surrogate && character >= 0xDFCE && character <= 0xE000) {
                    surrogate = false;
                    // Digit.
                    character -= 0xDFCE;
                    character %= 10;
                    character += 48;
                    builder.append(character);
                } else if (surrogate) {
                    surrogate = false;
                    Server.logError("Surrogate not defined: " + Integer.toHexString(character));
                } else {
                    surrogate = false;
                    builder.append(character);
                }
            }
            return builder.toString();
        }
    }

    private static final HashMap<Locale,Dictionary> DICTIONARY_MAP = new HashMap<>();

    private static synchronized ArrayList<Locale> getLocaleSet() {
        ArrayList<Locale> resultSet = new ArrayList<>();
        resultSet.addAll(DICTIONARY_MAP.keySet());
        return resultSet;
    }

    private static synchronized HashMap<Locale, Dictionary> getMap() {
        HashMap<Locale, Dictionary> resultMap = new HashMap<>();
        resultMap.putAll(DICTIONARY_MAP);
        return resultMap;
    }

    public static Dictionary getDictionary(Locale locale) {
        if (locale == null) {
            return null;
        } else {
            return DICTIONARY_MAP.get(locale);
        }
    }

    public static synchronized Dictionary removeDictionary(Locale locale) {
        if (locale == null) {
            return null;
        } else {
            return DICTIONARY_MAP.remove(locale);
        }
    }

    private static synchronized Dictionary newDictionary(Locale locale) {
        if (locale == null) {
            return null;
        } else {
            Dictionary dictionary = DICTIONARY_MAP.get(locale);
            if (dictionary == null) {
                dictionary = new Dictionary();
                DICTIONARY_MAP.put(locale, dictionary);
            }
            return dictionary;
        }
    }

    public static boolean addWord(Locale locale, String key, String word) {
        if (locale == null) {
            return false;
        } else if (key == null) {
            return false;
        } else if (word == null) {
            return false;
        } else {
            Dictionary dictionary = newDictionary(locale);
            if (dictionary.putWord(key, word)) {
                String lang = locale.toLanguageTag();
                Dictionary.append("PUT " + lang + " " + key + " " + word);
                return true;
            } else {
                return false;
            }
        }
    }

    public static boolean addRegex(Locale locale, String regex, String word) {
        if (locale == null) {
            return false;
        } else if (regex == null) {
            return false;
        } else if (word == null) {
            return false;
        } else {
            int time = TIME;
            Dictionary dictionary = newDictionary(locale);
            if (dictionary.putRegex(regex, word, time)) {
                String lang = locale.toLanguageTag();
                Dictionary.append("COMPILE " + lang + " " + regex + " " + word + " " + time);
                return true;
            } else {
                return false;
            }
        }
    }

    public static int writeWordSet(OutputStream outputStream) throws Exception {
        int count = 0;
        for (Locale locale : Dictionary.getLocaleSet()) {
            Dictionary dictionary = Dictionary.getDictionary(locale);
            if (dictionary != null) {
                String lang = locale.toLanguageTag();
                String word = dictionary.getFirstWord();
                while (word != null) {
                    outputStream.write(lang.getBytes("UTF-8"));
                    outputStream.write(' ');
                    outputStream.write(word.getBytes("UTF-8"));
                    outputStream.write('\n');
                    count++;
                    word = dictionary.getHigherWord(word);
                }
            }
        }
        return count;
    }

    public static int writeWordMap(OutputStream outputStream) throws Exception {
        int count = 0;
        for (Locale locale : Dictionary.getLocaleSet()) {
            Dictionary dictionary = Dictionary.getDictionary(locale);
            if (dictionary != null) {
                String lang = locale.toLanguageTag();
                for (String key : dictionary.getKeySet()) {
                    String word = dictionary.getWord(key);
                    outputStream.write(lang.getBytes("UTF-8"));
                    outputStream.write(' ');
                    outputStream.write(key.getBytes("UTF-8"));
                    outputStream.write(' ');
                    outputStream.write(word.getBytes("UTF-8"));
                    outputStream.write('\n');
                    count++;
                }
            }
        }
        return count;
    }

    public static int writeRegexMap(OutputStream outputStream) throws Exception {
        int count = 0;
        for (Locale locale : Dictionary.getLocaleSet()) {
            Dictionary dictionary = Dictionary.getDictionary(locale);
            if (dictionary != null) {
                String lang = locale.toLanguageTag();
                for (String regexKey : dictionary.getRegexSet()) {
                    Regex<String> regex = dictionary.getRegex(regexKey);
                    if (regex != null) {
                        outputStream.write(lang.getBytes("UTF-8"));
                        outputStream.write(' ');
                        outputStream.write(regexKey.getBytes("UTF-8"));
                        outputStream.write(' ');
                        outputStream.write(regex.getValue().getBytes("UTF-8"));
                        outputStream.write('\n');
                        outputStream.write(Integer.toString(regex.getLast()).getBytes("UTF-8"));
                        outputStream.write('\n');
                        count++;
                    }
                }
            }
        }
        return count;
    }

    public static int writeFlagMap(OutputStream outputStream) throws Exception {
        int count = 0;
        for (String key : Dictionary.getFlagKeySet()) {
            Regex<Flag> regex = getFlagRegex(key);
            if (regex == null) {
                removeFlagRegex(key);
            } else if (regex.isExpired(1)) {
                removeFlagRegex(key);
            } else {
                outputStream.write(regex.getValue().name().getBytes("UTF-8"));
                outputStream.write(' ');
                outputStream.write(key.getBytes("UTF-8"));
                outputStream.write(' ');
                outputStream.write(Integer.toString(regex.getLast()).getBytes("UTF-8"));
                outputStream.write('\n');
                count++;
            }
        }
        return count;
    }

    public static boolean addWord(Locale locale, String word) {
        if (locale == null) {
            return false;
        } else if (word == null) {
            return false;
        } else {
            Dictionary dictionary = newDictionary(locale);
            if (dictionary.addWord(word)) {
                String lang = locale.toLanguageTag();
                Dictionary.append("ADD " + lang + " " + word);
                return true;
            } else {
                return false;
            }
        }
    }

    public static boolean removeKey(Locale locale, String key) {
        if (locale == null) {
            return false;
        } else if (key == null) {
            return false;
        } else {
            Dictionary dictionary = getDictionary(locale);
            if (dictionary == null) {
                return false;
            } else if (dictionary.removeKey(key)) {
                if (dictionary.isEmpty()) {
                    removeDictionary(locale);
                }
                String lang = locale.toLanguageTag();
                Dictionary.append("DROP KEY " + lang + " " + key);
                return true;
            } else {
                return false;
            }
        }
    }

    public static boolean removeWord(Locale locale, String word) {
        if (locale == null) {
            return false;
        } else if (word == null) {
            return false;
        } else {
            Dictionary dictionary = getDictionary(locale);
            if (dictionary == null) {
                return false;
            } else if (dictionary.removeWord(word)) {
                if (dictionary.isEmpty()) {
                    removeDictionary(locale);
                }
                String lang = locale.toLanguageTag();
                Dictionary.append("DROP WORD " + lang + " " + word);
                return true;
            } else {
                return false;
            }
        }
    }

    public static boolean removeRegex(Locale locale, String regex) {
        if (locale == null) {
            return false;
        } else if (regex == null) {
            return false;
        } else {
            Dictionary dictionary = getDictionary(locale);
            if (dictionary == null) {
                return false;
            } else if (dictionary.removeRegex(regex)) {
                if (dictionary.isEmpty()) {
                    removeDictionary(locale);
                }
                String lang = locale.toLanguageTag();
                Dictionary.append("DROP REGEX " + lang + " " + regex);
                return true;
            } else {
                return false;
            }
        }
    }

    public static boolean dropFlag(String regex) {
        if (regex == null) {
            return false;
        } else if (removeFlag(regex)) {
            append("DROP FLAG " + regex);
            return true;
        } else {
            return false;
        }
    }

    private static final File FILE = new File("./data/dictionary.txt");
    private static Writer WRITER = null;
    private static final LinkedList<String> LIST = new LinkedList<>();
    private static final Semaphore SEMAPHORE = new Semaphore(0);
    
    private static void append(String line) {
        if (SEMAPHORE.tryAcquire()) {
            try {
                writeList();
                WRITER.append(line);
                WRITER.write('\n');
                WRITER.flush();
            } catch (Exception ex) {
                Server.logError(ex);
            } finally {
                SEMAPHORE.release();
            }
        } else {
            LIST.offer(line);
        }
    }
    
    private static void writeList() {
        try {
            String line;
            while ((line = LIST.poll()) != null) {
                WRITER.write(line);
                WRITER.write('\n');
            }
        } catch (Exception ex) {
            Server.logError(ex);
        }
    }
    
    private static void startWriter() {
        try {
            WRITER = new FileWriter(FILE, true);
            writeList();
            if (Core.isRunning()) {
                WRITER.flush();
            } else {
                WRITER.close();
            }
        } catch (Exception ex) {
            Server.logError(ex);
        } finally {
            if (Core.isRunning()) {
                SEMAPHORE.release();
            }
        }
    }

    public static void load() {
        long time = System.currentTimeMillis();
        if (FILE.exists()) {
            TreeMap<Integer, Integer> timeMap = new TreeMap<>();
            timeMap.put(TIME, TIME);
            String line;
            try (FileInputStream fis = new FileInputStream(FILE)) {
                // Reading BOM.
                int byte1 = fis.read();
                int byte2 = fis.read();
                int byte3 = fis.read();
                if (byte1 == 0xEF && byte2 == 0xBB && byte3 == 0xBF) {
                    // UTF-8 representation.
                    InputStreamReader isr = new InputStreamReader(fis, UTF_8);
                    BufferedReader reader = new BufferedReader(isr);
                    while ((line = reader.readLine()) != null) {
                        try {
                            StringTokenizer tokenizer = new StringTokenizer(line, " ");
                            if (tokenizer.hasMoreTokens()) {
                                String token = tokenizer.nextToken();
                                if (token.equals("ADD")) {
                                    Locale locale = Locale.forLanguageTag(tokenizer.nextToken());
                                    String word = tokenizer.nextToken();
                                    Integer last = tokenizer.hasMoreTokens() ? Integer.parseInt(tokenizer.nextToken()) : TIME;
                                    if (timeMap.containsKey(last)) {
                                        last = timeMap.get(last);
                                    } else {
                                        timeMap.put(last, last);
                                    }
                                    Dictionary dictionary = newDictionary(locale);
                                    dictionary.addWord(word, last);
                                } else if (token.equals("PUT")) {
                                    Locale locale = Locale.forLanguageTag(tokenizer.nextToken());
                                    String key = tokenizer.nextToken();
                                    String word = tokenizer.nextToken();
                                    Dictionary dictionary = newDictionary(locale);
                                    dictionary.putWord(key, word);
                                } else if (token.equals("COMPILE")) {
                                    Locale locale = Locale.forLanguageTag(tokenizer.nextToken());
                                    String regex = tokenizer.nextToken();
                                    String word = tokenizer.nextToken();
                                    int last = tokenizer.hasMoreTokens() ? Integer.parseInt(tokenizer.nextToken()) : TIME;
                                    Dictionary dictionary = newDictionary(locale);
                                    dictionary.putRegex(regex, word, last);
                                } else if (token.equals("FLAG")) {
                                    String flag = tokenizer.nextToken();
                                    String regex = tokenizer.nextToken();
                                    int last = tokenizer.hasMoreTokens() ? Integer.parseInt(tokenizer.nextToken()) : TIME;
                                    Dictionary.putFlag(flag, regex, last);
                                } else if (token.equals("DROP")) {
                                    token = tokenizer.nextToken();
                                    if (token.equals("WORD")) {
                                        Locale locale = Locale.forLanguageTag(tokenizer.nextToken());
                                        String word = tokenizer.nextToken();
                                        Dictionary dictionary = newDictionary(locale);
                                        dictionary.removeWord(word);
                                        if (dictionary.isEmpty()) {
                                            removeDictionary(locale);
                                        }
                                    } else if (token.equals("KEY")) {
                                        Locale locale = Locale.forLanguageTag(tokenizer.nextToken());
                                        String key = tokenizer.nextToken();
                                        Dictionary dictionary = newDictionary(locale);
                                        dictionary.removeKey(key);
                                        if (dictionary.isEmpty()) {
                                            removeDictionary(locale);
                                        }
                                    } else if (token.equals("REGEX")) {
                                        Locale locale = Locale.forLanguageTag(tokenizer.nextToken());
                                        String regex = tokenizer.nextToken();
                                        Dictionary dictionary = newDictionary(locale);
                                        dictionary.removeRegex(regex);
                                        if (dictionary.isEmpty()) {
                                            removeDictionary(locale);
                                        }
                                    }
                                } else if (token.equals("REP")) {
                                    String lang = tokenizer.nextToken();
                                    Locale locale = Locale.forLanguageTag(lang);
                                    String zone = tokenizer.nextToken();
                                    float xiSum = Float.parseFloat(tokenizer.nextToken());
                                    float xi2Sum = Float.parseFloat(tokenizer.nextToken());
                                    int last = Integer.parseInt(tokenizer.nextToken());
                                    String flag = tokenizer.nextToken();
                                    byte min = 0;
                                    byte max = 0;
                                    if (tokenizer.countTokens() > 1) {
                                        min = Byte.parseByte(tokenizer.nextToken());
                                        max = Byte.parseByte(tokenizer.nextToken());
                                    }
                                    Node.load(locale, zone, xiSum, xi2Sum, last, flag, min, max);
                                } else if (token.equals("QUEUE")) {
                                    String subject = new String(Core.BASE64STANDARD.decode(tokenizer.nextToken()), UTF_8);
                                    Byte value = tokenizer.hasMoreTokens() ? Byte.parseByte(tokenizer.nextToken()) : null;
                                    Locale locale = null;
                                    String recipient = null;
                                    if (tokenizer.hasMoreTokens()) {
                                        token = tokenizer.nextToken();
                                        if (!token.equals("NULL")) {
                                            locale = Locale.forLanguageTag(token);
                                        }
                                        if (tokenizer.hasMoreTokens()) {
                                            token = tokenizer.nextToken();
                                            if (!token.equals("NULL")) {
                                                recipient = token;
                                            }
                                        }
                                    }
                                    addOperation(subject, value, locale, recipient);
                                } else if (token.equals("DEFINE")) {
                                    Locale locale = Locale.forLanguageTag(tokenizer.nextToken());
                                    String key = tokenizer.nextToken();
                                    int last = tokenizer.hasMoreTokens() ? Integer.parseInt(tokenizer.nextToken()) : TIME;
                                    Dictionary dictionary = newDictionary(locale);
                                    dictionary.addUndefined(key, last);
                                } else if (token.equals("UNDEFINED")) {
                                    Locale locale = Locale.forLanguageTag(tokenizer.nextToken());
                                    String key = tokenizer.nextToken();
                                    short count = tokenizer.hasMoreTokens() ? Short.parseShort(tokenizer.nextToken()) : 0;
                                    int last = tokenizer.hasMoreTokens() ? Integer.parseInt(tokenizer.nextToken()) : TIME;
                                    Dictionary dictionary = newDictionary(locale);
                                    dictionary.setUndefined(key, count, last);
                                } else {
                                    Server.logError("comand not defined: " + token);
                                }
                            }
                        } catch (Exception ex) {
                            Server.logError(line);
                            Server.logError(ex);
                        }
                    }
                } else {
                    Server.logError("BOM not defined in file '" + FILE.getName() + "'.");
                }
                Server.logLoad(time, FILE);
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }
        startWriter();
    }

    public static boolean store() {
        refreshTime();
        try {
            long time = System.currentTimeMillis();
            SEMAPHORE.acquire();
            try {
                WRITER.close();
                Path source = FILE.toPath();
                Path temp = source.resolveSibling('.' + FILE.getName());
                try (FileOutputStream fos = new FileOutputStream(temp.toFile())) {
                    // White UTF-8 BOM.
                    fos.write(0xEF);
                    fos.write(0xBB);
                    fos.write(0xBF);
                    OutputStreamWriter osw = new OutputStreamWriter(fos, UTF_8);
                    BufferedWriter writer = new BufferedWriter(osw);
                    for (String key : getFlagKeySet()) {
                        Regex<Flag> regex = getFlagRegex(key);
                        if (regex == null) {
                            removeFlagRegex(key);
                        } else if (regex.isExpired(1)) {
                            removeFlagRegex(key);
                        } else {
                            writer.write("FLAG ");
                            writer.write(regex.getValue().name());
                            writer.write(' ');
                            writer.write(key);
                            writer.write(' ');
                            writer.write(Integer.toString(regex.getLast()));
                            writer.write('\n');
                            writer.flush();
                        }
                    }
                    HashMap<Locale, Dictionary> langMap = getMap();
                    for (Locale locale : langMap.keySet()) {
                        String language = locale.toLanguageTag();
                        Dictionary dictionary = langMap.get(locale);
                        if (dictionary.isEmpty()) {
                            removeDictionary(locale);
                        } else {
                            for (String word : dictionary.getWordSet()) {
                                writer.write("ADD ");
                                writer.write(language);
                                writer.write(' ');
                                writer.write(word);
                                writer.write('\n');
                                writer.flush();
                            }
                            for (String key : dictionary.getKeySet()) {
                                String word = dictionary.getWord(key);
                                if (word != null) {
                                    writer.write("PUT ");
                                    writer.write(language);
                                    writer.write(' ');
                                    writer.write(key);
                                    writer.write(' ');
                                    writer.write(word);
                                    writer.write('\n');
                                    writer.flush();
                                }
                            }
                            for (String regexKey : dictionary.getRegexSet()) {
                                Regex<String> regex = dictionary.getRegex(regexKey);
                                if (regex == null) {
                                    dictionary.removeRegex(regexKey);
                                } else if (regex.isExpired(4)) {
                                    dictionary.removeRegex(regexKey);
                                } else if (dictionary.containsKey(regex.getValue())) {
                                    dictionary.removeRegex(regexKey);
                                } else {
                                    writer.write("COMPILE ");
                                    writer.write(language);
                                    writer.write(' ');
                                    writer.write(regexKey);
                                    writer.write(' ');
                                    writer.write(regex.getValue());
                                    writer.write(' ');
                                    writer.write(Integer.toString(regex.getLast()));
                                    writer.write('\n');
                                    writer.flush();
                                }
                            }
                            for (String key : dictionary.getUndefinedKeySet()) {
                                Counter counter = dictionary.getUndefined(key);
                                if (counter == null) {
                                    dictionary.removeUndefined(key);
                                    continue;
                                } else if (counter.count == 0) {
                                    dictionary.removeUndefined(key);
                                    continue;
                                } else if (counter.isExpired()) {
                                    dictionary.removeUndefined(key);
                                    continue;
                                } else if (dictionary.containsWord(key)) {
                                    dictionary.removeUndefined(key);
                                    continue;
                                } else if (dictionary.containsKey(key)) {
                                    dictionary.removeUndefined(key);
                                    continue;
                                } else if (Core.isRunning() && dictionary.matches(key)) {
                                    dictionary.removeUndefined(key);
                                    continue;
                                }
                                writer.write("UNDEFINED ");
                                writer.write(language);
                                writer.write(' ');
                                writer.write(key);
                                writer.write(' ');
                                writer.write(Short.toString(counter.count));
                                writer.write(' ');
                                writer.write(Integer.toString(counter.last));
                                writer.write('\n');
                                writer.flush();
                            }
                        }
                    }
                    for (Locale locale : ROOT.keySet()) {
                        Node node = ROOT.get(locale);
                        node.store(writer, locale, ".");
                    }
                    THREAD.store(writer);
                }
                Files.move(temp, source, REPLACE_EXISTING);
                Server.logStore(time, FILE);
                return true;
            } finally {
                startWriter();
            }
        } catch (Exception ex) {
            Server.logError(ex);
            return false;
        }
    }

    private Phrase newPhrase(TreeSet<String> keySet) {
        if (keySet == null) {
            return null;
        } else {
            return new Phrase(keySet);
        }
    }

    private static final HashMap<Character,Character> LEET_MAP;
    
    static {
        LEET_MAP = new HashMap<>();
        LEET_MAP.put('4', 'A');
        LEET_MAP.put('3', 'B');
        LEET_MAP.put('(', 'C');
        LEET_MAP.put(')', 'D');
        LEET_MAP.put('3', 'E');
        LEET_MAP.put('6', 'G');
        LEET_MAP.put('1', 'L');
        LEET_MAP.put('0', 'O');
        LEET_MAP.put('5', 'S');
        LEET_MAP.put('7', 'T');
    }
        
    private class Phrase {

        private final TreeSet<String> SET = new TreeSet<>();
        private final TreeMap<String, String> MAP = new TreeMap<>();
        private final TreeSet<String> UNDEFINED = new TreeSet<>();

        private int score = 0;

        private Phrase(TreeSet<String> keySet) {
            for (String key : keySet) {
                processKey(key);
            }
        }

        private boolean processKey(String key) {
            String word;
            if (key == null) {
                return false;
            } else if (key.isEmpty()) {
                return false;
            } else if (key.matches("<[a-z0-9]+>")) {
                return SET.add(key);
            } else if ((word = getWord(key)) != null) {
                score += 5;
                return SET.add(word);
            } else if ((word = getWord(key.replaceAll("[0-9]+", "#"))) != null) {
                score += 5;
                return SET.add(word);
            } else if (containsWord(word = key)) {
                score += 5;
                MAP.put(key, word);
                return SET.add(word);
            } else if (key.length() == 1 && Character.isLetter(key.charAt(0))) {
                return SET.add("<letter>");
            } else if (key.matches("^20[0-5][0-9]$")) {
                return SET.add(key);
            } else if (key.matches("^[0-9]+$")) {
                return SET.add("<integer>");
            } else if (key.length() > 1 && containsWord(word = key.substring(0, 1).toUpperCase() + key.substring(1).toLowerCase())) {
                score += 4;
                MAP.put(key, word);
                return SET.add(word);
            } else if (containsWord(word = key.toLowerCase()) && key.equals(key.toUpperCase())) {
                score += 4;
                MAP.put(key, word);
                return SET.add(word);
            } else if (key.length() > 1 && containsWord(word = key.toLowerCase()) && key.equals(key.substring(0, 1).toUpperCase() + key.substring(1).toLowerCase())) {
                score += 4;
                MAP.put(key, word);
                return SET.add(word);
            } else if ((word = getMatch(key)) != null) {
                score += 3;
                return SET.add(word);
            } else if ((word = decodeLeet(key)) != null) {
                score += 2;
                SET.add("<leet>");
                return SET.add(word);
            } else if (key.contains("(") || key.contains(")")) {
                boolean added = false;
                for (String split : key.split("[()]")) {
                    if (processKey(split)) {
                        added = true;
                    }
                }
                return added;
            } else if (key.contains(".")) {
                boolean added = false;
                for (String split : key.split("\\.")) {
                    if (processKey(split)) {
                        added = true;
                    }
                }
                return added;
            } else if (key.contains("/")) {
                boolean added = false;
                for (String split : key.split("/")) {
                    if (processKey(split)) {
                        added = true;
                    }
                }
                return added;
            } else if (key.contains("-")) {
                boolean added = false;
                for (String split : key.split("-")) {
                    if (processKey(split)) {
                        added = true;
                    }
                }
                if (!added) {
                    UNDEFINED.add(key);
                }
                return added;
            } else {
                UNDEFINED.add(key);
                return false;
            }
        }
        
        private String decodeLeet(String key) {
            if (key == null) {
                return null;
            } else {
                int upperCaseCount = 0;
                for (char encoded : key.toCharArray()) {
                    if (Character.isUpperCase(encoded)) {
                        upperCaseCount++;
                    }
                }
                if (upperCaseCount > key.length() / 2) {
                    key = key.replace('l', 'I');
                }
                key = key.toUpperCase();
                StringBuilder builder = new StringBuilder();
                for (char encoded : key.toCharArray()) {
                    Character decoded = LEET_MAP.get(encoded);
                    if (decoded == null) {
                        builder.append(encoded);
                    } else {
                        builder.append(decoded);
                    }
                }
                String word = key;
                key = builder.toString();
                if (word.equals(key)) {
                    return null;
                } else if ((word = getWord(key)) != null) {
                    return word;
                } else if (containsWord(word = key)) {
                    return word;
                } else if (key.length() > 1 && containsWord(word = key.substring(0, 1).toUpperCase() + key.substring(1).toLowerCase())) {
                    return word;
                } else if (containsWord(word = key.toLowerCase()) && key.equals(key.toUpperCase())) {
                    return word;
                } else if (key.length() > 1 && containsWord(word = key.toLowerCase()) && key.equals(key.substring(0, 1).toUpperCase() + key.substring(1).toLowerCase())) {
                    return word;
                } else if ((word = getMatch(key)) != null) {
                    return word;
                } else {
                    return null;
                }
            }
        }

        public int getScore() {
            return score;
        }
        
        public void incrementScore() {
            score++;
        }

        public TreeSet<String> getSet() {
            return SET;
        }

        public TreeSet<String> getUndefined() {
            return UNDEFINED;
        }

        public TreeMap<String, String> getMap() {
            return MAP;
        }

        private Dictionary getDictionary() {
            return Dictionary.this;
        }

        @Override
        public String toString() {
            return SET.toString() + " = " + score;
        }
    }

    private static final net.spfbl.core.Regex SPAM_PATTERN = new net.spfbl.core.Regex("\\B("
            + "SPAM:|"
            + "-SPAM-|"
            + "\\[SPAM\\]|"
            + "\\*SPAM\\*|"
            + "\\*\\*\\*Spam\\*\\*\\*"
            + ")\\B"
    );

    private static final net.spfbl.core.Regex EMAIL_PATTERN = new net.spfbl.core.Regex("\\b"
            + "[0-9a-zA-Z_-][0-9a-zA-Z._+-]*"
            + "@"
            + "(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])"
            + "(\\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9]))*)"
            + "\\b"
    );

    private static final net.spfbl.core.Regex IPV4_PATTERN = new net.spfbl.core.Regex("\\b"
            + "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}"
            + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
            + "\\b"
    );

    private static final net.spfbl.core.Regex IPV6_PATTERN = new net.spfbl.core.Regex("\\b"
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
            + "\\b"
    );

    private static final net.spfbl.core.Regex URL_PATTERN = new net.spfbl.core.Regex("(?i)\\b("
            + "(https?\\:\\/\\/([a-z0-9\\._-]+|\\[[a-f0-9\\:]+\\])"
            + "(:[0-9]{1,6})?[a-z0-9\\-\\._~!\\$&\\(\\)\\*+,;\\=:\\/?@#]*)"
            + "|"
            + "(www\\.[a-z0-9\\._-]+\\.([a-z]{2,5})"
            + "(\\/[a-z0-9\\-\\._~!\\$&\\(\\)\\*+,;=:\\/?@#]*)?)"
            + ")\\b"
    );

    private static final net.spfbl.core.Regex FQDN_PATTERN = new net.spfbl.core.Regex("(?i)\\b("
            + "[a-z0-9\\._-]+\\.(com|org|net|int|edu|gov|mil|"
            + "ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|"
            + "ba|bb|bd|be|bf|bg|bh|bi|bj|bl|bm|bn|bo|bq|br|bs|bt|bv|"
            + "bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|"
            + "cw|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|"
            + "fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|"
            + "gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|"
            + "io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|"
            + "ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mf|"
            + "mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|"
            + "na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|"
            + "pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|"
            + "sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|"
            + "sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|"
            + "ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|"
            + "za|zm|zw)"
            + ")\\b"
    );
    
    private static final net.spfbl.core.Regex DATE_PATTERN = new net.spfbl.core.Regex("\\b("
            + "[0-3][0-9]/(0[1-9]|1[0-2])(/20[0-9][0-9])?|"
            + "(0[1-9]|1[0-2])/[0-3][0-9](/20[0-9][0-9])?|"
            + "[0-3][0-9]-(0[1-9]|1[0-2])-20[0-9][0-9]|"
            + "(0[1-9]|1[0-2])-[0-3][0-9]-20[0-9][0-9]|"
            + "20[0-9][0-9]-[0-1][0-9]-[0-3][0-9]|"
            + "(0[1-9]|1[0-2])/20[0-9][0-9]|"
            + "[0-3][0-9] (January|February|March|April|May|June|July|August|September|October|November|December)( 20[0-9][0-9])?"
            + ")\\b"
    );

    private static final net.spfbl.core.Regex TIME_PATTERN = new net.spfbl.core.Regex("\\b("
            + "(0?[0-9]|1[0-1]):[0-5][0-9]( AM| PM)?"
            + "|"
            + "([0-1]?[0-9]|2[0-3]):[0-5][0-9](:[0-5][0-9])?"
            + "|"
            + "([0-1][0-9]|2[0-3])h([0-5][0-9])?"
            + ")\\b"
    );

    private static final net.spfbl.core.Regex HASHTAG_PATTERN = new net.spfbl.core.Regex(
            "\\B#[0-9a-zA-Z]+\\b"
    );

    private static final net.spfbl.core.Regex PROFILE_PATTERN = new net.spfbl.core.Regex(
            "\\B@[0-9a-zA-Z_]+\\b"
    );

    private static final net.spfbl.core.Regex PERCENTAGE_PATTERN = new net.spfbl.core.Regex(
            "\\b[0-9]+%\\B"
    );

    private static final net.spfbl.core.Regex TEMPERATURE_PATTERN = new net.spfbl.core.Regex(
            "\\b-?[0-9]+º(C|F)\\b"
    );
    
    private static final net.spfbl.core.Regex DEGREE_PATTERN = new net.spfbl.core.Regex(
            "\\b[0-9]+º\\b"
    );
    
    private static final net.spfbl.core.Regex BYTES_PATTERN = new net.spfbl.core.Regex(
            "\\b[0-9]+(B|KB|MB|GB|TB)\\b"
    );

    private static final net.spfbl.core.Regex PRICE_PATTERN = new net.spfbl.core.Regex(
            "((\\B\\$) ?(([1-9]\\d{0,2}(,\\d{3})*)|(([1-9]\\d*)?\\d))(\\.\\d\\d)?|"
                    + "(\\B€|\\bR\\$) ?(([1-9]\\d{0,2}(.\\d{3})*)|(([1-9]\\d*)?\\d))(\\,\\d\\d)?|"
                    + "(([1-9]\\d{0,2}(.\\d{3})*)|(([1-9]\\d*)?\\d))(\\,\\d\\d)? ?€\\B)"

    );
    
    private static final net.spfbl.core.Regex INTEGER_PATTERN = new net.spfbl.core.Regex("("
            + "\\([0-9]+\\)"
            + "|"
            + "["
            + "\u2460-\u2473"
            + "\u2776-\u277F"
            + "\u24EB\u24FF"
            + "\u2776\u277F"
            + "\u24F5\u24FE"
            + "]+"
            + ")"
    );
    
    private static final net.spfbl.core.Regex EMOJI_PATTERN = new net.spfbl.core.Regex("[\\s\n\r]*("
            + "?:("
            + "?:[\u00a9\u00ae\u203c\u2049\u2122\u2139\u2194-\u2199\u21a9-\u21aa"
            + "\u231a-\u231b\u2328\u23cf\u23e9-\u23f3\u23f8-\u23fa\u24c2"
            + "\u25aa-\u25ab\u25b6\u25c0\u25fb-\u25fe\u2600-\u2604\u260e\u2611"
            + "\u2614-\u2615\u2618\u261d\u2620\u2622-\u2623\u2626\u262a"
            + "\u262e-\u262f\u2638-\u263a\u2648-\u2653\u2660\u2663\u2665-\u2666"
            + "\u2668\u267b\u267f\u2692-\u2694\u2696-\u2697\u2699\u269b-\u269c"
            + "\u26a0-\u26a1\u26aa-\u26ab\u26b0-\u26b1\u26bd-\u26be\u26c4-\u26c5"
            + "\u26c8\u26ce-\u26cf\u26d1\u26d3-\u26d4\u26e9-\u26ea\u26f0-\u26f5"
            + "\u26f7-\u26fa\u26fd\u2702\u2705\u2708-\u270d\u270f\u2712\u2714"
            + "\u2716\u271d\u2721\u2728\u2733-\u2734\u2744\u2747\u274c\u274e"
            + "\u2753-\u2755\u2757\u2763-\u2764\u2795-\u2797\u27a1\u27b0\u27bf"
            + "\u2934-\u2935\u2b05-\u2b07\u2b1b-\u2b1c\u2b50\u2b55\u3030\u303d"
            + "\u3297\u3299\ud83c\udc04\ud83c\udccf\ud83c\udd70-\ud83c\udd71"
            + "\ud83c\udd7e-\ud83c\udd7f\ud83c\udd8e\ud83c\udd91-\ud83c\udd9a"
            + "\ud83c\ude01-\ud83c\ude02\ud83c\ude1a\ud83c\ude2f\ud83c"
            + "\ude32-\ud83c\ude3a\ud83c\ude50-\ud83c\ude51\u200d\ud83c"
            + "\udf00-\ud83d\uddff\ud83d\ude00-\ud83d\ude4f\ud83d\ude80-\ud83d"
            + "\udeff\ud83e\udd00-\ud83e\uddff\udb40\udc20-\udb40\udc7f]|"
            + "\u200d[\u2640\u2642]|"
            + "[\ud83c\udde6-\ud83c\uddff]{2}|"
            + ".[\u20e0\u20e3\ufe0f]+"
            + ")+[\\s\n\r]*"
            + ")+");
    
    private static final net.spfbl.core.Regex IDEOGRAPH_PATTERN = new net.spfbl.core.Regex("["
            + "\u4e00-\u9fff" // Unified ideographs
            + "\u3040-\u309f\u30a0-\u30ff\uff00-\uffef" // Japanese ideographs
            + "\u2e80-\u2fd5\u3190-\u319f\u3400-\u4dbf\uf900-\ufaad" // Chinese ideographs
            + "\uac00-\ud7a3\u1100-\u11ff\u3130-\u318f\ua960-\ua97f\ud7b0-\ud7ff" // Korean ideographs
            + "]"
    );

    private static boolean isRead(String subject) {
        if (subject == null) {
            return false;
        } else if (subject.startsWith("Read: ")) {
            return true;
        } else if (subject.startsWith("Read-Receipt: ")) {
            return true;
        } else if (subject.startsWith("Lida: ")) {
            return true;
        } else {
            return false;
        }
    }

    private static boolean isReply(String subject) {
        if (subject == null) {
            return false;
        } else if (subject.startsWith("re:")) {
            return true;
        } else if (subject.startsWith("Re:")) {
            return true;
        } else if (subject.startsWith("RE:")) {
            return true;
        } else if (subject.startsWith("res:")) {
            return true;
        } else if (subject.startsWith("Res:")) {
            return true;
        } else if (subject.startsWith("RES:")) {
            return true;
        } else if (subject.startsWith("aw:")) {
            return true;
        } else if (subject.startsWith("Aw:")) {
            return true;
        } else if (subject.startsWith("AW:")) {
            return true;
        } else if (subject.startsWith("ref:")) {
            return true;
        } else if (subject.startsWith("Ref:")) {
            return true;
        } else if (subject.startsWith("REF:")) {
            return true;
        } else if (subject.startsWith("rif:")) {
            return true;
        } else if (subject.startsWith("Rif:")) {
            return true;
        } else if (subject.startsWith("RIF:")) {
            return true;
        } else {
            return false;
        }
    }

    private static boolean isForward(String subject) {
        if (subject == null) {
            return false;
        } else if (subject.startsWith("fwd:")) {
            return true;
        } else if (subject.startsWith("Fwd:")) {
            return true;
        } else if (subject.startsWith("FWD:")) {
            return true;
        } else if (subject.startsWith("fw:")) {
            return true;
        } else if (subject.startsWith("Fw:")) {
            return true;
        } else if (subject.startsWith("FW:")) {
            return true;
        } else if (subject.startsWith("enc:")) {
            return true;
        } else if (subject.startsWith("Enc:")) {
            return true;
        } else if (subject.startsWith("ENC:")) {
            return true;
        } else if (subject.startsWith("wg:")) {
            return true;
        } else if (subject.startsWith("Wg:")) {
            return true;
        } else if (subject.startsWith("WG:")) {
            return true;
        } else if (subject.startsWith("tr:")) {
            return true;
        } else if (subject.startsWith("Tr:")) {
            return true;
        } else if (subject.startsWith("TR:")) {
            return true;
        } else if (subject.startsWith("rv:")) {
            return true;
        } else if (subject.startsWith("Rv:")) {
            return true;
        } else if (subject.startsWith("RV:")) {
            return true;
        } else if (subject.startsWith("i:")) {
            return true;
        } else if (subject.startsWith("I:")) {
            return true;
        } else {
            return false;
        }
    }

    private static boolean isUndeliverable(String subject) {
        if (subject == null) {
            return false;
        } else if (subject.startsWith("Undeliverable: ")) {
            return true;
        } else {
            return false;
        }
    }
    
    public static String toString(
            String subject, Locale defaultLocale,
            String recipient, int minimum
    ) {
        Entry<Locale,TreeSet<String>> subset = Dictionary.getSubset(
                subject, defaultLocale, recipient
        );
        if (subset == null) {
            return null;
        } else if (subset.getValue().size() < minimum) {
            return null;
        } else {
            return subset.toString();
        }
    }
    
    public static Entry<Locale, TreeSet<String>> getSubset(String subject) {
        return getSubset(subject, Locale.getDefault(), null);
    }

    public static Entry<Locale, TreeSet<String>> getSubset(
            String subject, Locale defaultLocale, String recipient
    ) {
        if (subject == null) {
            return null;
        } else {
            TreeSet<String> keySet = new TreeSet<>();
            subject = normalizeCharacters(subject);
            subject = subject.replace('°', 'º');
            subject = subject.trim();
            if (subject.endsWith("?")) {
                keySet.add("<question>");
            } else if (subject.endsWith("!")) {
                keySet.add("<exclamation>");
            } else if (subject.endsWith("...")) {
                keySet.add("<ellipsis>");
            }
            boolean prefix;
            do {
                if (isRead(subject)) {
                    int index = subject.indexOf(':') + 1;
                    subject = subject.substring(index).trim();
                    keySet.add("<read>");
                    prefix = true;
                } else if (isReply(subject)) {
                    int index = subject.indexOf(':') + 1;
                    subject = subject.substring(index).trim();
                    keySet.add("<reply>");
                    prefix = true;
                } else if (isForward(subject)) {
                    int index = subject.indexOf(':') + 1;
                    subject = subject.substring(index).trim();
                    keySet.add("<forward>");
                    prefix = true;
                } else if (isUndeliverable(subject)) {
                    int index = subject.indexOf(':') + 1;
                    subject = subject.substring(index).trim();
                    keySet.add("<undeliverable>");
                    prefix = true;
                } else {
                    prefix = false;
                }
            } while (prefix);
            
            Matcher matcher = SPAM_PATTERN.createMatcher(subject);
            while (matcher.find()) {
                String spam = matcher.group();
                subject = subject.replace(spam, " ");
                keySet.add("<spam>");
            }
            SPAM_PATTERN.offerMatcher(matcher);
            
            matcher = EMAIL_PATTERN.createMatcher(subject);
            while (matcher.find()) {
                String email = matcher.group();
                subject = subject.replace(email, " ");
                email = normalizeEmail(email);
                recipient = normalizeEmail(recipient);
                if (Objects.equals(email, recipient)) {
                    keySet.add("<recipient>");
                } else {
                    keySet.add("<email>");
                }
            }
            EMAIL_PATTERN.offerMatcher(matcher);
            
            matcher = IPV4_PATTERN.createMatcher(subject);
            while (matcher.find()) {
                String ipv4 = matcher.group();
                subject = subject.replace(ipv4, " ");
                keySet.add("<ipv4>");
            }
            IPV4_PATTERN.offerMatcher(matcher);
            
            matcher = IPV6_PATTERN.createMatcher(subject);
            while (matcher.find()) {
                String ipv6 = matcher.group();
                if (ipv6.length() > 2) {
                    subject = subject.replace(ipv6, " ");
                    keySet.add("<ipv6>");
                }
            }
            IPV6_PATTERN.offerMatcher(matcher);
            
            matcher = URL_PATTERN.createMatcher(subject);
            while (matcher.find()) {
                String url = matcher.group();
                subject = subject.replace(url, " ");
                keySet.add("<url>");
            }
            URL_PATTERN.offerMatcher(matcher);
            
            matcher = FQDN_PATTERN.createMatcher(subject);
            String recipientDomain = net.spfbl.whois.Domain.extractHost(recipient, false);
            recipientDomain = net.spfbl.whois.Domain.normalizeHostname(recipientDomain, false);
            while (matcher.find()) {
                String fqdn = matcher.group();
                subject = subject.replace(fqdn, " ");
                fqdn = net.spfbl.whois.Domain.normalizeHostname(fqdn, false);
                if (Objects.equals(fqdn, recipientDomain)) {
                    keySet.add("<recipient>");
                } else {
                    keySet.add("<fqdn>");
                }
            }
            FQDN_PATTERN.offerMatcher(matcher);
            
            matcher = DATE_PATTERN.createMatcher(subject);
            while (matcher.find()) {
                String date = matcher.group();
                subject = subject.replace(date, " ");
                keySet.add("<date>");
            }
            DATE_PATTERN.offerMatcher(matcher);
            
            matcher = TIME_PATTERN.createMatcher(subject);
            while (matcher.find()) {
                String time = matcher.group();
                subject = subject.replace(time, " ");
                keySet.add("<time>");
            }
            TIME_PATTERN.offerMatcher(matcher);
            
            matcher = HASHTAG_PATTERN.createMatcher(subject);
            while (matcher.find()) {
                String hashtag = matcher.group();
                subject = subject.replace(hashtag, " ");
                keySet.add("<hashtag>");
            }
            HASHTAG_PATTERN.offerMatcher(matcher);
            
            matcher = PROFILE_PATTERN.createMatcher(subject);
            while (matcher.find()) {
                String profile = matcher.group();
                subject = subject.replace(profile, " ");
                keySet.add("<profile>");
            }
            PROFILE_PATTERN.offerMatcher(matcher);
            
            matcher = PERCENTAGE_PATTERN.createMatcher(subject);
            while (matcher.find()) {
                String percentage = matcher.group();
                subject = subject.replace(percentage, " ");
                keySet.add("<percentage>");
            }
            PERCENTAGE_PATTERN.offerMatcher(matcher);
            
            matcher = TEMPERATURE_PATTERN.createMatcher(subject);
            while (matcher.find()) {
                String temperature = matcher.group();
                subject = subject.replace(temperature, " ");
                keySet.add("<temperature>");
            }
            TEMPERATURE_PATTERN.offerMatcher(matcher);
            
            matcher = DEGREE_PATTERN.createMatcher(subject);
            while (matcher.find()) {
                String degree = matcher.group();
                subject = subject.replace(degree, " ");
                keySet.add("<degree>");
            }
            DEGREE_PATTERN.offerMatcher(matcher);
            
            matcher = BYTES_PATTERN.createMatcher(subject);
            while (matcher.find()) {
                String bytes = matcher.group();
                subject = subject.replace(bytes, " ");
                keySet.add("<bytes>");
            }
            BYTES_PATTERN.offerMatcher(matcher);
            
            matcher = PRICE_PATTERN.createMatcher(subject);
            while (matcher.find()) {
                String price = matcher.group();
                subject = subject.replace(price, " ");
                keySet.add("<price>");
            }
            PRICE_PATTERN.offerMatcher(matcher);
            
            matcher = INTEGER_PATTERN.createMatcher(subject);
            while (matcher.find()) {
                String integer = matcher.group();
                subject = subject.replace(integer, " ");
                keySet.add("<integer>");
            }
            INTEGER_PATTERN.offerMatcher(matcher);
            
            matcher = EMOJI_PATTERN.createMatcher(subject);
            while (matcher.find()) {
                String emoji = matcher.group();
                subject = subject.replace(emoji, " ");
                if (emoji.equals("…")) {
                    keySet.add("<ellipsis>");
                } else if (emoji.equals("©")) {
                    keySet.add("<copyright>");
                } else if (emoji.equals("®")) {
                    keySet.add("<registered>");
                } else {
                    keySet.add("<emoji>");
                }
            }
            EMOJI_PATTERN.offerMatcher(matcher);
            
            matcher = IDEOGRAPH_PATTERN.createMatcher(subject);
            while (matcher.find()) {
                String ideograph = matcher.group();
                subject = subject.replace(ideograph, " ");
                keySet.add(ideograph);
            }
            IDEOGRAPH_PATTERN.offerMatcher(matcher);
            
            
            String[] splited = subject.split("[\\s\\[\\]{}=\\:;,?!|_]+");
            for (String key : splited) {
                key = key.replaceFirst("^[^\\p{IsAlphabetic}\\p{Digit}(]+", "");
                key = key.replaceFirst("[^\\p{IsAlphabetic}\\p{Digit})]+$", "");
                if (!key.isEmpty()) {
                    String normalized = normalizeToOcidental(key);
                    keySet.add(normalized);
                    if (!normalized.equals(key)) {
                        keySet.add("<leet>");
                    }
                }
            }
            if (keySet.isEmpty()) {
                return null;
            } else {
                int score1 = 0;
                HashMap<Locale,Phrase> phraseMap = new HashMap<>();
                HashMap<Locale,Dictionary> dictionaryMap = getMap();
                for (Locale locale : dictionaryMap.keySet()) {
                    Dictionary dictionary = dictionaryMap.get(locale);
                    Phrase phrase = dictionary.newPhrase(keySet);
                    if (locale.equals(defaultLocale)) {
                        phrase.incrementScore();
                    }
                    phraseMap.put(locale, phrase);
                    if (score1 < phrase.getScore()) {
                        score1 = phrase.getScore();
                    }
                }
                if (score1 == 0) {
                    return null;
                } else {
                    int score2 = 0;
                    for (Locale locale : phraseMap.keySet()) {
                        Phrase phrase = phraseMap.get(locale);
                        if (score1 == phrase.getScore()) {
                            if (score2 < phrase.getScore()) {
                                score2 = phrase.getScore();
                            }
                        }
                    }
                    int size = phraseMap.size() + 1;
                    ArrayList<Locale> localeList = new ArrayList<>(size);
                    if (phraseMap.containsKey(defaultLocale)) {
                        localeList.add(defaultLocale);
                    }
                    localeList.addAll(phraseMap.keySet());
                    int time = TIME;
                    for (Locale locale : localeList) {
                        String language = locale.toLanguageTag();
                        Phrase phrase = phraseMap.get(locale);
                        if (score2 == phrase.getScore()) {
                            Dictionary dictionary = phrase.getDictionary();
                            TreeMap<String, String> wordMap = phrase.getMap();
                            for (String key : wordMap.keySet()) {
                                String word = wordMap.get(key);
                                dictionary.putWord(locale, key, word);
                            }
                            for (String key : phrase.getUndefined()) {
                                if (dictionary.addUndefined(key, time)) {
                                    append("DEFINE " + language + " " + key + " " + time);
                                }
                            }
                            return new SimpleEntry<>(locale, phrase.getSet());
                        }
                    }
                }
            }
            return null;
        }
    }

    private static final HashMap<Locale,Node> ROOT = new HashMap<>();

    private static Node getRoot(Locale locale) {
        if (locale == null) {
            return null;
        } else {
            Node node = ROOT.get(locale);
            if (node == null) {
                node = new Node();
                ROOT.put(locale, node);
            }
            return node;
        }
    }

    public static boolean addHarmful(
            String subject, Locale locale, String recipient
    ) {
        return addOperation(subject, (byte) -4, locale, recipient);
    }

    public static boolean addUndesirable(
            String subject, Locale locale, String recipient
    ) {
        return addOperation(subject, (byte) -2, locale, recipient);
    }

    public static boolean addUnacceptable(
            String subject, Locale locale, String recipient
    ) {
        return addOperation(subject, (byte) -1, locale, recipient);
    }

    public static boolean addAcceptable(
            String subject, Locale locale, String recipient
    ) {
        return addOperation(subject, (byte) 1, locale, recipient);
    }

    public static boolean addDesirable(
            String subject, Locale locale, String recipient
    ) {
        return addOperation(subject, (byte) 2, locale, recipient);
    }

    public static boolean addBeneficial(
            String subject, Locale locale, String recipient
    ) {
        return addOperation(subject, (byte) 4, locale, recipient);
    }

    private static boolean addOperation(
            String key, Byte value, Locale locale, String recipient
    ) {
        if (key == null) {
            return false;
        } else if (value == null) {
            return false;
        } else {
            Parameter parameter = new Parameter(value, locale, recipient);
            THREAD.offer(new SimpleImmutableEntry<>(key, parameter));
            return true;
        }
    }
    
    private static final class Parameter {
        
        private final byte value;
        private final Locale locale;
        private final String recipient;
        
        private Parameter(byte value, Locale locale, String recipient) {
            this.value = value;
            this.locale = locale;
            this.recipient = recipient;
        }
        
        private byte getValue() {
            return value;
        }
        
        private Locale getLocale() {
            return locale;
        }
        
        private String getRecipient() {
            return recipient;
        }
    }

    private static final ProcessThread THREAD = new ProcessThread();

    public static void startThread() {
        THREAD.start();
    }

    public static void terminateThread() {
        THREAD.terminate();
    }

    private static class ProcessThread extends Thread {

        private final LinkedList<SimpleImmutableEntry> QUEUE = new LinkedList<>();
        private boolean run = true;

        private ProcessThread() {
            super("DICTTHRED");
            setPriority(Thread.MIN_PRIORITY);
        }

        private void offer(SimpleImmutableEntry<String,Parameter> entry) {
            QUEUE.offer(entry);
            notifyQueue();
        }

        private SimpleImmutableEntry<String,Parameter> poll() {
            return QUEUE.poll();
        }

        private synchronized void waitNext() {
            try {
                wait(60000);
            } catch (InterruptedException ex) {
                Server.logError(ex);
            }
        }

        private boolean continueRun() {
            return run;
        }

        public void terminate() {
            run = false;
            notifyQueue();
        }

        public synchronized void notifyQueue() {
            notify();
        }

        @Override
        public void run() {
            try {
                Server.logTrace("thread started.");
                SimpleImmutableEntry<String,Parameter> entry;
                while (Core.isRunning() && continueRun()) {
                    while (Core.isRunning() && (entry = poll()) != null) {
                        String subject = entry.getKey();
                        Parameter parameter = entry.getValue();
                        byte value = parameter.getValue();
                        Locale locale = parameter.getLocale();
                        String recipient = parameter.getRecipient();
                        process(subject, value, locale, recipient);
                    }
                    waitNext();
                }
            } finally {
                Server.logTrace("thread closed.");
            }
        }

        private void store(BufferedWriter writer) throws IOException {
            if (!Core.isRunning()) {
                SimpleImmutableEntry<String,Parameter> entry;
                while ((entry = poll()) != null) {
                    String subject = entry.getKey();
                    Parameter parameter = entry.getValue();
                    byte value = parameter.getValue();
                    Locale locale = parameter.getLocale();
                    String recipient = parameter.getRecipient();
                    writer.write("QUEUE ");
                    writer.write(Core.BASE64STANDARD.encodeToString(subject.getBytes("UTF-8")));
                    writer.write(' ');
                    writer.write(Byte.toString(value));
                    writer.write(' ');
                    if (locale == null) {
                        writer.write("NULL");
                    } else {
                        writer.write(locale.toLanguageTag());
                    }
                    writer.write(' ');
                    if (recipient == null) {
                        writer.write("NULL");
                    } else {
                        writer.write(recipient);
                    }
                    writer.write('\n');
                    writer.flush();
                }
            }
        }
    }
    
    private static ArrayList<Pivot> getDecendentList(
            Pivot root, TreeSet<String> wordSet
    ) {
        int n = wordSet.size() * wordSet.size() * wordSet.size();
        ArrayList<Pivot> childList = new ArrayList<>(n);
        for (String word1 : wordSet) {
            Pivot child1 = root.newPivot(word1);
            if (child1 != null) {
                childList.add(child1);
                for (String word2 : wordSet) {
                    Pivot child2 = child1.newPivot(word2);
                    if (child2 != null) {
                        childList.add(child2);
                        for (String word3 : wordSet) {
                            Pivot child3 = child2.newPivot(word3);
                            if (child3 != null) {
                                childList.add(child3);
                            }
                        }
                    }
                }
            }
        }
        Collections.sort(childList);
        return childList;
    }
    
    private static TreeSet<Pivot> getPivotSet(
            Locale locale, TreeSet<String> wordSet
    ) {
        TreeSet<Pivot> pivotSet = new TreeSet<>();
        Pivot root = new Pivot(0, ".", getRoot(locale), null);
        pivotSet.add(root);
        for (Pivot decendent : getDecendentList(root, wordSet)) {
            if (decendent.remove(wordSet)) {
                pivotSet.add(decendent);
                Pivot parent = decendent;
                while ((parent = parent.getParent()) != null) {
                    pivotSet.add(parent);
                }
            }
        }
        return pivotSet;
    }
    
    protected static void process(
            String subject, byte value,
            Locale defaultLocale, String recipient
    ) {
        Entry<Locale,TreeSet<String>> subset = Dictionary.getSubset(
                subject, defaultLocale, recipient
        );
        if (subset != null) {
            Locale locale = subset.getKey();
            TreeSet<String> wordSet = subset.getValue();
            for (Pivot pivot : getPivotSet(locale, wordSet)) {
                pivot.addValue(locale, value);
            }
        }
    }
    
    private static class Pivot implements Comparable<Pivot> {

        private int level;
        private String zone;
        private Node node;
        private Pivot parent;

        private Pivot(int level, String zone, Node node, Pivot parent) {
            this.level = level;
            this.zone = zone;
            this.node = node;
            this.parent = parent;
        }
        
        private Pivot newPivot(String word) {
            if (word == null) {
                return null;
            } else if (zone.contains('.' + word + '.')) {
                return null;
            } else {
                Node child = node.newChild(word);
                if (child == null) {
                    return null;
                } else {
                    return new Pivot(level + 1, zone + word + '.', child, this);
                }
            }
        }

        private Pivot newPivot(TreeSet<String> wordSet, boolean flagged) {
            if (wordSet == null) {
                return null;
            } else if (level == 3) {
                return null;
            } else if (wordSet.isEmpty()) {
                return null;
            } else {
                Node nodeMin = null;
                String wordMin = null;
                float stdMin = Float.MAX_VALUE;
                for (String word : wordSet) {
                    Node child = node.newChild(word);
                    if (child != null) {
                        if (!flagged || child.hasFlag()) {
                            float std = child.getSTD(level + 1);
                            if (std < stdMin) {
                                nodeMin = child;
                                wordMin = word;
                                stdMin = std;
                            }
                        }
                    }
                }
                if (nodeMin == null) {
                    return null;
                } else if (wordMin == null) {
                    return null;
                } else if (wordSet.remove(wordMin)) {
                    return new Pivot(level + 1, zone + wordMin + '.', nodeMin, this);
                } else {
                    return null;
                }
            }
        }

        private Flag getFlag(Flag defaultFlag) {
            return node.getFlag(defaultFlag);
        }
        
        private Pivot getParent() {
            return parent;
        }

        private void addValue(Locale locale, int value) {
            node.addValue(value, level);
            node.refreshFlag(locale, zone, level);
        }

        private float getSTD() {
            return node.getSTD(level);
        }
        
        private boolean remove(Set<String> wordSet) {
            if (wordSet == null) {
                return false;
            } else if (wordSet.isEmpty()) {
                return false;
            } else {
                TreeSet<String> removeSet = new TreeSet<>();
                StringTokenizer tokenizer = new StringTokenizer(zone, ".");
                while (tokenizer.hasMoreTokens()) {
                    String word = tokenizer.nextToken();
                    if (wordSet.contains(word)) {
                        removeSet.add(word);
                    } else {
                        return false;
                    }
                }
                wordSet.removeAll(removeSet);
                return true;
            }
        }

        @Override
        public int compareTo(Pivot other) {
            float stdThis = this.getSTD();
            float stdOther = other.getSTD();
            int compare = Float.compare(stdThis, stdOther);
            if (compare == 0) {
                return this.zone.compareTo(other.zone);
            } else {
                return compare;
            }
        }
        
        @Override
        public String toString() {
            return zone;
        }
    }
    
    private static final HashMap<String,Regex<Flag>> FLAG_MAP = new HashMap<>();
    
    public static boolean putFlag(
            String flag, String regex
    ) throws PatternSyntaxException, IllegalArgumentException {
        return putFlag(flag, regex, TIME);
    }

    public static boolean putFlag(
            String flag, String regex, int last
    ) throws PatternSyntaxException, IllegalArgumentException {
        if (flag == null) {
            return false;
        } else if (regex == null) {
            return false;
        } else if (putFlag(regex, new Regex(regex, Flag.valueOf(flag), last))) {
            Dictionary.append("FLAG " + flag + " " + regex + " " + last);
            return true;
        } else {
            return false;
        }
    }

    private synchronized static boolean putFlag(String key, Regex<Flag> regex) {
        if (key == null) {
            return false;
        } else if (regex == null) {
            return false;
        } else {
            Regex<Flag> oldValue = FLAG_MAP.put(key, regex);
            if (oldValue == null) {
                return true;
            } else {
                return oldValue.getValue() != regex.getValue();
            }
        }
    }

    private synchronized static boolean removeFlag(String key) {
        if (key == null) {
            return false;
        } else {
            return FLAG_MAP.remove(key) != null;
        }
    }

    private synchronized static HashMap<String,Regex<Flag>> getFlagMap() {
        HashMap<String,Regex<Flag>> flagMap = new HashMap<>();
        flagMap.putAll(FLAG_MAP);
        return flagMap;
    }

    private synchronized static TreeSet<String> getFlagKeySet() {
        TreeSet<String> resultSet = new TreeSet<>();
        resultSet.addAll(FLAG_MAP.keySet());
        return resultSet;
    }
    
    private synchronized static Regex<Flag> getFlagRegex(String key) {
        if (key == null) {
            return null;
        } else {
            return FLAG_MAP.get(key);
        }
    }
    
    private synchronized static boolean removeFlagRegex(String key) {
        if (key == null) {
            return false;
        } else {
            return FLAG_MAP.remove(key) != null;
        }
    }
    
    public static Flag getFlagREGEX(String subject) {
        if (subject == null) {
            return null;
        } else if (subject.isEmpty()) {
            return null;
        } else {
            boolean harmful = false;
            boolean undesirable = false;
            boolean unacceptable = false;
            boolean acceptable = false;
            boolean desirable = false;
            boolean beneficial = false;
            for (String key : getFlagKeySet()) {
                Regex<Flag> regex = getFlagRegex(key);
                if (regex != null) {
                    switch (regex.getValue()) {
                        case HARMFUL:
                            if (!harmful && regex.matches(subject)) {
                                harmful = true;
                            }
                            break;
                        case UNDESIRABLE:
                            if (!undesirable && regex.matches(subject)) {
                                undesirable = true;
                            }
                            break;
                        case UNACCEPTABLE:
                            if (!unacceptable && regex.matches(subject)) {
                                unacceptable = true;
                            }
                            break;
                        case ACCEPTABLE:
                            if (!acceptable && regex.matches(subject)) {
                                acceptable = true;
                            }
                            break;
                        case DESIRABLE:
                            if (!desirable && regex.matches(subject)) {
                                desirable = true;
                            }
                            break;
                        case BENEFICIAL:
                            if (!beneficial && regex.matches(subject)) {
                                beneficial = true;
                            }
                            break;
                    }
                    if ((harmful || undesirable) && (desirable || beneficial)) {
                        return null;
                    }
                }
            }
            if ((harmful || undesirable) && (desirable || beneficial)) {
                return null;
            } else if (harmful) {
                return HARMFUL;
            } else if (beneficial) {
                return BENEFICIAL;
            } else if (undesirable) {
                return UNDESIRABLE;
            } else if (desirable) {
                return DESIRABLE;
            } else if (unacceptable) {
                return UNACCEPTABLE;
            } else if (acceptable) {
                return ACCEPTABLE;
            } else {
                return null;
            }
        }
    }
    
    public static String getREGEX(String subject) {
        if (subject == null) {
            return null;
        } else {
            String harmful = null;
            String undesirable = null;
            String unacceptable = null;
            String acceptable = null;
            String desirable = null;
            String beneficial = null;
            for (String key : getFlagKeySet()) {
                Regex<Flag> regex = getFlagRegex(key);
                if (regex != null) {
                    switch (regex.getValue()) {
                        case HARMFUL:
                            if (harmful == null && regex.matches(subject)) {
                                harmful = regex.pattern();
                            }
                            break;
                        case UNDESIRABLE:
                            if (undesirable == null && regex.matches(subject)) {
                                undesirable = regex.pattern();
                            }
                            break;
                        case UNACCEPTABLE:
                            if (unacceptable == null && regex.matches(subject)) {
                                unacceptable = regex.pattern();
                            }
                            break;
                        case ACCEPTABLE:
                            if (acceptable == null && regex.matches(subject)) {
                                acceptable = regex.pattern();
                            }
                            break;
                        case DESIRABLE:
                            if (desirable == null && regex.matches(subject)) {
                                desirable = regex.pattern();
                            }
                            break;
                        case BENEFICIAL:
                            if (beneficial == null && regex.matches(subject)) {
                                beneficial = regex.pattern();
                            }
                            break;
                    }
                    if ((harmful != null || undesirable != null) && (desirable != null || beneficial != null)) {
                        return null;
                    }
                }
            }
            if ((harmful != null || undesirable != null) && (desirable != null || beneficial != null)) {
                return null;
            } else if (harmful != null) {
                return harmful;
            } else if (beneficial != null) {
                return beneficial;
            } else if (undesirable != null) {
                return undesirable;
            } else if (desirable != null) {
                return desirable;
            } else if (unacceptable != null) {
                return unacceptable;
            } else if (acceptable != null) {
                return acceptable;
            } else {
                return null;
            }
        }
    }
    
    public static Flag getFlag(String subject, Locale defaultLocale, String recipient) {
        return getFlag(subject, defaultLocale, recipient, true);
    }

    public static Flag getFlag(String subject, Locale defaultLocale, String recipient, boolean regex) {
        if (subject == null) {
            return UNACCEPTABLE;
        } else if (subject.length() == 0) {
            return UNACCEPTABLE;
        } else {
            Flag flag = regex ? getFlagREGEX(subject) : null;
            if (flag == null) {
                Entry<Locale, TreeSet<String>> entry = Dictionary.getSubset(
                        subject, defaultLocale, recipient
                );
                if (entry == null) {
                    return UNACCEPTABLE;
                } else {
                    Locale locale = entry.getKey();
                    TreeSet<String> wordSet = entry.getValue();
                    Pivot root = new Pivot(0, ".", getRoot(locale), null);
                    boolean spam = false;
                    boolean ham = false;
                    for (Pivot decendent : getDecendentList(root, wordSet)) {
                        if (decendent.remove(wordSet)) {
                            Flag newFlag = decendent.getFlag(Flag.ACCEPTABLE);
                            if (newFlag != null) {
                                if (flag == null) {
                                    flag = newFlag;
                                }
                                switch (newFlag) {
                                    case HARMFUL:
                                    case UNDESIRABLE:
                                        spam = true;
                                        break;
                                    case BENEFICIAL:
                                    case DESIRABLE:
                                        ham = true;
                                        break;
                                }
                            }
                        }
                    }
                    if (spam && ham) {
                        return Flag.ACCEPTABLE;
                    } else if (flag == null) {
                        return Flag.ACCEPTABLE;
                    } else {
                        return flag;
                    }
                }
            } else {
                return flag;
            }
        }
    }
    
    private static final int POPULATION[] = {
        1024, 512, 256, 128
    };

    private static class Node extends Reputation {

        private Node() {
            super();
        }

        private Node(Node other) {
            super(other, 2.0f);
        }

        private void addValue(int value, int level) {
            if (level == 0) {
                if (value == 4) {
                    value = 2;
                } else if (value == -4) {
                    value = -2;
                }
            }
            super.add(value, POPULATION[level]);
        }

        private float getSTD(int level) {
            float[] xisArray = getXiSum();
            float xis = xisArray[0];
            float xi2s = xisArray[1];
            float avg = xis / POPULATION[level];
            float std = xi2s;
            std -= 2 * avg * xis;
            std += POPULATION[level] * avg * avg;
            std /= POPULATION[level] - 1;
            return std;
        }
        
        @Override
        public Flag getFlag() {
            Object flag = getFlagObject();
            if (flag instanceof Flag) {
                return (Flag) flag;
            } else {
                return null;
            }
        }

        private TreeMap<String,Node> MAP = null;

        private synchronized Node newChild(String key) {
            Flag flag = getFlag();
            if (key == null) {
                return null;
            } else if (flag == null) {
                return null;
            } else {
                Node node = null;
                if (MAP == null) {
                    MAP = new TreeMap<>();
                } else {
                    node = MAP.get(key);
                }
                if (node == null) {
                    node = new Node(this);
                    MAP.put(key, node);
                }
                return node;
            }
        }

        private synchronized void clearMap() {
            MAP = null;
        }

        private synchronized void dropMap(String key) {
            if (MAP != null) {
                MAP.remove(key);
                if (MAP.isEmpty()) {
                    MAP = null;
                }
            }
        }

        private synchronized TreeSet<String> keySet() {
            TreeSet<String> keySet = new TreeSet<>();
            if (MAP != null) {
                keySet.addAll(MAP.keySet());
            }
            return keySet;
        }

        private synchronized Node getReputation(String key) {
            if (MAP == null) {
                return null;
            } else {
                return MAP.get(key);
            }
        }

        private Flag refreshFlag(Locale locale, String zone, int level) {
            Flag oldFlag = getFlag();
            Flag newFlag = refreshFlag(
                    POPULATION[level], false
            );
            if (newFlag != oldFlag) {
                float[] xisArray = getXiSum();
                byte[] extremes = getExtremes();
                int last = getLast();
                append(
                        "REP " + locale.toLanguageTag() + " " + zone + " "
                        + xisArray[0] + " " + xisArray[1] + " "
                        + last + " " + newFlag + " "
                        + extremes[0] + " " + extremes[1]
                );
            }
            return newFlag;
        }

        private static void load(
                Locale locale,
                String zone,
                float xiSum,
                float xi2Sum,
                int last,
                String flag,
                byte minimum,
                byte maximum
        ) {
            try {
                StringTokenizer tokenizer = new StringTokenizer(zone, ".");
                Node node = getRoot(locale);
                while (node != null && tokenizer.hasMoreTokens()) {
                    String key = tokenizer.nextToken();
                    node = node.newChild(key);
                }
                if (node != null) {
                    node.set(xiSum, xi2Sum, last, flag, minimum, maximum);
                }
            } catch (Exception ex) {
                Server.logError(ex);
            }
        }

        private void store(BufferedWriter writer, Locale locale, String zone) throws IOException {
            Object flag = getFlagObject();
            boolean store = true;
            if (flag instanceof Integer) {
                store = (Integer) flag > 0;
            }
            if (store) {
                float[] xiResult = getXiSum();
                byte[] extremes = getExtremes();
                int last = getLast();
                writer.write("REP ");
                writer.write(locale.toLanguageTag());
                writer.write(' ');
                writer.write(zone);
                writer.write(' ');
                writer.write(Float.toString(xiResult[0]));
                writer.write(' ');
                writer.write(Float.toString(xiResult[1]));
                writer.write(' ');
                writer.write(Integer.toString(last));
                writer.write(' ');
                writer.write(flag.toString());
                writer.write(' ');
                writer.write(Byte.toString(extremes[0]));
                writer.write(' ');
                writer.write(Byte.toString(extremes[1]));
                writer.write('\n');
                writer.flush();
                if (flag instanceof Integer) {
                    clearMap();
                } else if (flag == Flag.HARMFUL && extremes[0] == -4 && extremes[1] == -4 && zone.length() > 1) {
                    clearMap();
                } else if (flag == Flag.UNDESIRABLE && extremes[0] == -2 && extremes[1] == -2 && zone.length() > 1) {
                    clearMap();
                } else if (flag == Flag.UNACCEPTABLE && extremes[0] == -1 && extremes[1] == -1 && zone.length() > 1) {
                    clearMap();
                } else if (flag == Flag.ACCEPTABLE && extremes[0] == 1 && extremes[1] == 1 && zone.length() > 1) {
                    clearMap();
                } else if (flag == Flag.DESIRABLE && extremes[0] == 2 && extremes[1] == 2 && zone.length() > 1) {
                    clearMap();
                } else if (flag == Flag.BENEFICIAL && extremes[0] == 4 && extremes[1] == 4 && zone.length() > 1) {
                    clearMap();
                } else {
                    for (String key : keySet()) {
                        Node reputation = getReputation(key);
                        if (reputation != null) {
                            if (reputation.isExpired()) {
                                dropMap(key);
                            } else {
                                reputation.store(writer, locale, zone + key + '.');
                            }
                        }
                    }
                }
            }
        }
    }
}
