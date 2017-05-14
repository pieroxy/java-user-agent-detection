package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
class Matcher {
    String pattern;
    MatchingType matchType;
    public MatchingType getMatchType() {
        return matchType;
    }

    public Matcher(String s, MatchingType m) {
        pattern = s;
        matchType = m;
    }

    public boolean match(String token) {
        return matchType.matches(token, pattern);
    }
    @Override
    public String toString() {
        return matchType.name() + "(" + pattern + ")";
    }
}