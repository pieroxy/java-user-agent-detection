package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
class Matcher {
    String pattern;
    MatchingType match;

    public Matcher(String s, MatchingType m) {
        pattern = s;
        match = m;
    }

    public boolean match(String token) {
        return match.matches(token, pattern);
    }
    @Override
    public String toString() {
        return match.name() + "(" + pattern + ")";
    }
}