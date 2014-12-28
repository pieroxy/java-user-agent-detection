package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
class UserAgentContext {
    private static final boolean DEBUG = false;
    private String debug = "";
    private String ua;
    private String lcua;
    private List<String> tokens = new LinkedList<String>();
    private List<String> parenTokens = new LinkedList<String>();
    private List<String> ignoredTokens = new ArrayList<String>();
    private List<String> consumedTokens = new ArrayList<String>();

    public UserAgentContext(String u) {
        //System.out.println("\r\nBuilding context for: " + u);
        if (u != null) {
            if (u.charAt(0) == '"' && u.charAt(u.length()-1) == '"') {
                u = u.substring(1,u.length()-1);
            }
            if (u.length()>1) {
                ua = u;
                lcua = u.toLowerCase();

                String work = ua;
                int pos;
                while ((pos=work.lastIndexOf("("))>-1) {
                    int pos2 = work.indexOf(")",pos);
                    if (pos2<0) pos2 = work.length();
                    String parenContent = work.substring(pos+1,pos2);
                    addParenTokens(parenContent);
                    //System.out.println("rebuilding work = " + pos + " " + pos2 + " " + work.length());
                    work = work.substring(0,pos) + ((pos2<work.length())?(" " + work.substring(pos2+1,work.length())) : "");
                    //System.out.println("tmp work = " + work);
                }
                StringTokenizer stw = new StringTokenizer(work," ");
                while (stw.hasMoreTokens()) {
                    tokens.add(stw.nextToken().trim());
                }
            }
        }

    }

    public String debugContext() {
        return "UA: " + ua + "\r\n" +
               "LCUA: " + lcua + "\r\n" +
               "TOKENS: " + debug(tokens) + "\r\n" +
               "(OKEN): " + debug(parenTokens);
    }
    private static String debug(List<String> l) {
        if (l==null) return "<null>";
        if (l.size() < 1) return "";
        StringBuilder sb = new StringBuilder(l.size() * 15);
        sb.append("{ ");
        for (String s : l) {
            sb.append("\"").append(s.replaceAll("\"","\\\"")).append("\", ");
        }
        return sb.substring(0,sb.length()-2) + "}";
    }
    private static String debug(String[] l) {
        if (l == null) return "<null>";
        if (l.length < 1) return "";
        StringBuilder sb = new StringBuilder(l.length * 15);
        sb.append("{ ");
        for (String s : l) {
            sb.append("\"").append(s.replaceAll("\"","\\\"")).append("\", ");
        }
        return sb.substring(0,sb.length()-2) + "}";
    }
    private static String debug(Matcher[] l) {
        if (l == null) return "<null>";
        if (l.length < 1) return "";
        StringBuilder sb = new StringBuilder(l.length * 15);
        sb.append("{ ");
        for (Matcher s : l) {
            sb.append("\"").append(s.toString().replaceAll("\"","\\\"")).append("\", ");
        }
        return sb.substring(0,sb.length()-2) + "}";
    }

    private void addParenTokens(String s) {
        //System.out.println("paren token parsing: " + s);
        StringTokenizer stw = new StringTokenizer(s,";");
        while (stw.hasMoreTokens()) {
            s = stw.nextToken().trim();
            if (s.length()>0) {
                if (s.matches("[0-9a-zA-Z\\.-]+/[0-9a-zA-Z\\.-]+(( )+[0-9a-zA-Z\\.-]+/[0-9a-zA-Z\\.-]+)+")) {
                    StringTokenizer stw2 = new StringTokenizer(s," ");
                    while (stw2.hasMoreTokens()) {
                        s = stw2.nextToken().trim();
                        parenTokens.add(s);
                    }
                } else {
                    parenTokens.add(s);
                }
            }
        }
    }
    private String[]getAndConsumeTokens(Matcher[]match, List<String> _tokens, List<String> consumeTo) {
        if (DEBUG) System.out.println("getAndConsumeTokens " + debug(tokens) + " matching " + debug(match));
        ListIterator<String> it = _tokens.listIterator();
        String[] res = new String[match.length];
        int i = 0;
        while (it.hasNext()) {
            String token = it.next();
            if (DEBUG) System.out.println(i + ":" + token);
            boolean matched = match[i].match(token);
            if (matched) {
                if (DEBUG) System.out.println("matched");
                it.remove();
                if (DEBUG) System.out.println("_tokens is " + getRegularTokens());
                consumeTo.add(token);
                res[i++] = token;
                if (i == match.length) {
                    if (DEBUG) System.out.println("return " + debug(res));
                    return res;
                }
            } else {
                if (DEBUG) System.out.println("not matched. Rewinding by " + i);
                if (i>0) {
                    while (i>0) {
                        it.previous();
                        it.add(res[--i]);
                        matched = true;
                        consumeTo.remove(consumeTo.size()-1);
                    }
                    it.next();
                }
            }
        }
        if (i<match.length && i>0) {
            if (DEBUG) System.out.println("end reached && not matched. Rewinding by " + i);
            boolean first = true;
            while (i>0) {
                if (!first) it.previous();
                it.add(res[--i]);
                first = false;
                consumeTo.remove(consumeTo.size()-1);
                first = false;
            }
        }
        if (DEBUG) System.out.println("return null");
        return null;
    }

    /*
    * Token matching
    */

    private String getAndConsumeToken(Matcher match, List<String> _tokens, List<String> consumeTo) {
        Iterator<String> it = _tokens.iterator();
        while (it.hasNext()) {
            String token = it.next();
            if (match.match(token)) {
                if (_tokens != consumeTo) {
                    it.remove();
                    consumeTo.add(token);
                }
                return token;
            }
        }
        return null;
    }
    private static String getToken(Matcher match, List<String> _tokens) {
        Iterator<String> it = _tokens.iterator();
        while (it.hasNext()) {
            String token = it.next();
            if (match.match(token)) {
                return token;
            }
        }
        return null;
    }



    /*
    * Region matching
    */
    private String getAndConsumeToken(Matcher match, MatchingRegion region, List<String> consumeTo) {
        String res;
        if (region.includesRegular()) {
            res = getAndConsumeToken(match, tokens, consumeTo);
            if (res != null) return res;
        }
        if (region.includesParenthesis()) {
            res = getAndConsumeToken(match, parenTokens, consumeTo);
            return res;
        }
        if (region == MatchingRegion.CONSUMED) {
            return getAndConsumeToken(match, consumedTokens, consumeTo);
        }
        return null;
    }
    private String[] getAndConsumeTokens(Matcher[] match, MatchingRegion region, List<String> consumeTo) {
        String[] res;
        if (region.includesRegular()) {
            res = getAndConsumeTokens(match, tokens, consumeTo);
            if (res != null) return res;
        }
        if (region.includesParenthesis()) {
            res = getAndConsumeTokens(match, parenTokens, consumeTo);
            return res;
        }
        if (region == MatchingRegion.CONSUMED) {
            return getAndConsumeTokens(match, consumedTokens, consumeTo);
        }
        return null;
    }

    /*
    * Utilities
    */



    private static String keepPos(String version, int position) {
        if (version == null) return null;
        int pd = 0;
        for (int i=0 ; i<version.length() ; i++) {
            if (!Character.isDigit(version.charAt(i))) {
                pd++;
                if (pd>=position) return version.substring(0,i);
            }
        }
        return version;
    }


    private static String getVersionNumber(String s, int a_position) {
        if (a_position<0) return "";
        StringBuffer res = new StringBuffer();
        int status = 0;

        while (a_position < s.length()) {
            char c = s.charAt(a_position);
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
                if (Character.isDigit(c)) {
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
    private String getFirstVersionNumber(String s, int a_position, int numDigits) {
        String ver = getVersionNumber(s, a_position);
        if (ver==null) return "";
        int i = 0;
        String res="";
        while (i<ver.length() && i<numDigits) {
            res+=String.valueOf(ver.charAt(i));
            i++;
        }
        return res;
    }


    /* Unit testing */
    public static void test() {
        UserAgentContext context = new UserAgentContext("a b c (d/3.3;e;f) g h i (j; k 2; l");
        String s;
        String[]ss;

        if (!context.getRegularTokens().equals("{ \"a\", \"b\", \"c\", \"g\", \"h\", \"i\"}")) throw new RuntimeException("Fail 1: " + context.getRegularTokens());
        if (!context.getParenTokens().equals("{ \"j\", \"k 2\", \"l\", \"d/3.3\", \"e\", \"f\"}")) throw new RuntimeException("Fail 2: " + context.getParenTokens());
        if (!String.valueOf(s=context.getcVersionAfterPattern("d/",MatchingType.BEGINS,MatchingRegion.REGULAR)).equals("null")) throw new RuntimeException("Fail 3: " + s);
        if (!String.valueOf(s=context.getcVersionAfterPattern("d/",MatchingType.BEGINS,MatchingRegion.PARENTHESIS)).equals("3.3")) throw new RuntimeException("Fail 4: " + s + " " + context.getDebug());
        if (!String.valueOf(s=context.getcVersionAfterPattern("d/",MatchingType.BEGINS,MatchingRegion.PARENTHESIS)).equals("null")) throw new RuntimeException("Fail 5: " + s);
        if (!context.getParenTokens().equals("{ \"j\", \"k 2\", \"l\", \"e\", \"f\"}")) throw new RuntimeException("Fail 6: " + context.getParenTokens());

        if (!Arrays.equals(ss=context.getcNextTokens(new Matcher[] {new Matcher("g",MatchingType.EQUALS),
            new Matcher("h",MatchingType.EQUALS)
        }, MatchingRegion.REGULAR),
        new String[] {"g","h"})) {
            throw new RuntimeException("Fail 7: " + debug(ss) + " remains " + context.getRegularTokens());
        }
        if (!context.getRegularTokens().equals("{ \"a\", \"b\", \"c\", \"i\"}")) throw new RuntimeException("Fail 8: " + context.getRegularTokens());
        if (null != (ss=context.getcNextTokens(new Matcher[] {new Matcher("a",MatchingType.EQUALS),
            new Matcher("b",MatchingType.EQUALS),
            new Matcher("i",MatchingType.EQUALS)
        }, MatchingRegion.REGULAR))) {
            throw new RuntimeException("Fail 9: " + debug(ss) + " remains " + context.getRegularTokens());
        }
        if (!context.getRegularTokens().equals("{ \"a\", \"b\", \"c\", \"i\"}")) throw new RuntimeException("Fail 9: " + context.getRegularTokens());
        if (null != (ss=context.getcNextTokens(new Matcher[] {new Matcher("c",MatchingType.EQUALS),
            new Matcher("i",MatchingType.EQUALS),
            new Matcher("i",MatchingType.EQUALS)
        }, MatchingRegion.REGULAR))) {
            throw new RuntimeException("Fail 10: " + debug(ss) + " remains " + context.getRegularTokens());
        }
        if (!context.getRegularTokens().equals("{ \"a\", \"b\", \"c\", \"i\"}")) throw new RuntimeException("Fail 11: " + context.getRegularTokens());

    }

    /* public API */
    public String getToken(Matcher match, MatchingRegion region) {
        String res;
        if (region.includesRegular()) {
            res = getToken(match, tokens);
            if (res != null) return res;
        }
        if (region.includesParenthesis()) {
            res = getToken(match, parenTokens);
            return res;
        }
        if (region == MatchingRegion.CONSUMED) {
            return getToken(match, consumedTokens);
        }
        return null;
    }

    // Gets and consumes a token if found. Returns the version number after the pattern inside the token
    public String getcVersionAfterPattern(String pattern, MatchingType match, MatchingRegion region) {
        Matcher matcher = new Matcher(pattern, match);
        String token = getAndConsumeToken(matcher, region, consumedTokens);
        if (token == null) return null;
        return getVersionNumber(token,matcher.match.endOfMatchPosition(token, pattern));
    }
    public String getcVersionAfterPattern(String pattern, MatchingType match, MatchingRegion region, int nbPos) {
        return keepPos(getcVersionAfterPattern(pattern, match, region), nbPos);
    }
    // Consumes a token if found. Returns true if the token was found
    public boolean consume(String pattern, MatchingType match, MatchingRegion region) {
        return null != getcToken(pattern, match, region);
    }
    // Consumes a token if found. Returns true if the token was found
    public boolean ignore(String pattern, MatchingType match, MatchingRegion region) {
        return getAndConsumeToken(new Matcher(pattern, match), region, ignoredTokens) != null;
    }
// Consumes a token if found. Returns true if the token was found
    public String getcToken(String pattern, MatchingType match, MatchingRegion region) {
        return getAndConsumeToken(new Matcher(pattern, match), region, consumedTokens);
    }
    // Returns true if the pattern is matched in a token of the specified region.
    public boolean contains(String pattern, MatchingType match, MatchingRegion region) {
        return (null != getToken(new Matcher(pattern, match), region));
    }
    public String[] getcNextTokens(Matcher[]matchers, MatchingRegion region) {
        return getAndConsumeTokens(matchers, region, consumedTokens);
    }
    public String[] ignoreNextTokens(Matcher[]matchers, MatchingRegion region) {
        return getAndConsumeTokens(matchers, region, ignoredTokens);
    }

    public void ignoreAllTokens() {
        while (null != getAndConsumeToken(new Matcher("",MatchingType.ALWAYS_MATCH), MatchingRegion.BOTH, ignoredTokens));
    }

    public String getUA() {
        return ua;
    }
    String getDebug() {
        return debug;
    }
    public String getLCUA() {
        return lcua;
    }

    public String getRemainingTokens() {
        if (tokens.isEmpty() && parenTokens.isEmpty()) return "";
        StringBuilder sb = new StringBuilder((tokens.size() + parenTokens.size())*15);
        sb.append("{ ");
        for (String s : tokens) {
            sb.append("\"").append(s.replaceAll("\"","\\\"")).append("\", ");
        }
        for (String s : parenTokens) {
            sb.append("\"").append(s.replaceAll("\"","\\\"")).append("\", ");
        }
        return sb.substring(0,sb.length()-2) + "}";
    }

    public String getIgnoredTokens() {
        return debug(ignoredTokens);
    }

    public String getConsumedTokens() {
        return debug(consumedTokens);
    }
    public String getRegularTokens() {
        return debug(tokens);
    }
    public Iterator<String> getRegularTokensIterator() {
        return Collections.unmodifiableList(tokens).iterator();
    }
    public Iterator<String> getParenTokensIterator() {
        return Collections.unmodifiableList(parenTokens).iterator();
    }
    public String getParenTokens() {
        return debug(parenTokens);
    }

    public void debug(String s) {
        debug += "\r\n" + s;
    }
}