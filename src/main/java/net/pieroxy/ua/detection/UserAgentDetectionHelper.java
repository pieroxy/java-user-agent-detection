package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
class UserAgentDetectionHelper {
    static void consumeMozilla(UserAgentContext context) {
        context.consume("compatible", MatchingType.CONTAINS, MatchingRegion.PARENTHESIS);
        context.consume("Mozilla/", MatchingType.BEGINS, MatchingRegion.REGULAR);
    }

    static String getVersionNumber(String a_userAgent, int a_position) {
        if (a_position<0) return "";
        StringBuffer res = new StringBuffer();
        int status = 0;

        while (a_position < a_userAgent.length()) {
            char c = a_userAgent.charAt(a_position);
            switch (status) {
            case 0: // No valid digits encountered yet
                if (c == ' ' || c=='/') break;
                if (c == ';' || c==')') return "";
                status = 1;
            case 1: // Version number in progress
                if (c == ';' || c=='/' || c==')' || c=='(' || c=='[' || c=='%' || c==',') return res.toString().replace('_','.').trim();
                if (c == ' ') status = 2;
                res.append(c);
                break;
            case 2: // Space encountered - Might need to end the parsing
                if (/*(Character.isLetter(c) &&
                     Character.isLowerCase(c)) ||*/
                    Character.isDigit(c)) {
                    res.append(c);
                    status=1;
                } else
                    return res.toString().replace('_','.').trim();
                break;
            }
            a_position++;
        }
        return res.toString().replace('_','.').trim();
    }

    static String getFirstVersionNumber(String a_userAgent, int a_position, int numDigits) {
        String ver = getVersionNumber(a_userAgent, a_position);
        if (ver==null) return "";
        int i = 0;
        String res="";
        while (i<ver.length() && i<numDigits) {
            res+=String.valueOf(ver.charAt(i));
            i++;
        }
        return res;
    }
    static void addExtensionsCommonForLibs(UserAgentContext context, UserAgentDetectionResult res) {
        String ver;
        if (context.consume("AppEngine-Google;", MatchingType.EQUALS, MatchingRegion.REGULAR)) {
            context.consume("+http://code.google", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            ver = context.getcVersionAfterPattern("appid: ",MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            res.addExtension(new Extension("AppEngine-Google",ver));
        }

    }



}