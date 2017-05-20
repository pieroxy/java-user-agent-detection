package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
class StringUtils {
    public static boolean isNullOrEmpty(String s) {
        return s==null || s.length()==0;
    }
    public static String format(float f) {
        return String.valueOf(f);
    }
    /**
    * Gets a more concise version number. For example, getShortVersion("1.2.3", 2) gives "1.2" while getShortVersion("1.2.3", 1) gives "1".
    */
    public static String getShortVersion(String version, int nbChunks) {
        String sv = "";
        int chunk = 0;
        for (int i=0 ; i<version.length() ; i++) {
            char c = version.charAt(i);
            if (c == '.') {
                chunk++;
                if (chunk >= nbChunks) break;
                sv += c;
            } else if (Character.isDigit(c)) {
                sv += c;
            } else break;
        }
        return sv;
    }
}