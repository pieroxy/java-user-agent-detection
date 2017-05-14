package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
enum MatchingType {

    BEGINS {
        @Override
        public boolean matches(String token, String pattern) {
            return token.startsWith(pattern);
        }
        public int endOfMatchPosition (String token, String pattern) {
            if (token.startsWith(pattern)) return pattern.length();
            return -1;
        }
    },
    BEGINSIGNORECASE {
        @Override
        public boolean matches(String token, String pattern) {
            return token.regionMatches(true, 0, pattern, 0, pattern.length());
        }
        public int endOfMatchPosition (String token, String pattern) {
            if (matches(token,pattern)) return pattern.length();
            return -1;
        }
    },
    ENDS {
        @Override
        public boolean matches(String token, String pattern) {
            return token.endsWith(pattern);
        }
        public int endOfMatchPosition (String token, String pattern) {
            if (token.endsWith(pattern)) return token.length();
            return -1;
        }
    },
    EQUALS {
        @Override
        public boolean matches(String token, String pattern) {
            return token.equals(pattern);
        }
        public int endOfMatchPosition  (String token, String pattern) {
            if (token.equals(pattern)) return token.length();
            return -1;
        }
    },
    EQUALSIGNORECASE {
        @Override
        public boolean matches(String token, String pattern) {
            return token.equalsIgnoreCase(pattern);
        }
        public int endOfMatchPosition  (String token, String pattern) {
            if (token.equalsIgnoreCase(pattern)) return token.length();
            return -1;
        }
    },
    CONTAINS {
        @Override
        public boolean matches(String token, String pattern) {
            return token.contains(pattern);
        }
        public int endOfMatchPosition  (String token, String pattern) {
            int pos = token.indexOf(pattern);
            if (pos == -1) return -1;
            return pos + pattern.length();
        }
    },
    ALWAYS_MATCH {
        @Override
        public boolean matches(String token, String pattern) {
            return true;
        }
        public int endOfMatchPosition  (String token, String pattern) {
            return -1;
        }
    },
    REGEXP{
        @Override
        public boolean matches(String token, String pattern) {
            return token.matches(pattern);
        }
        public int endOfMatchPosition  (String token, String pattern) {
            return -1;
        }
    };

    public abstract boolean matches(String token, String pattern);
    public abstract int endOfMatchPosition (String token, String pattern);
}