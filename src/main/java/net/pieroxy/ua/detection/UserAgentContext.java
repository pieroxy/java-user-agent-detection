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
        if (u != null) {
            if (u.length()>0 && u.charAt(0) == '"' && u.charAt(u.length()-1) == '"') {
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
                    work = work.substring(0,pos) + ((pos2<work.length())?(" " + work.substring(pos2+1,work.length())) : "");
                }
                String[]stw = work.split(" ");
                for (String ss:stw) {
                    String token = ss.trim();
                    if (token.length()>0)
                        tokens.add(token);
                }
            } else
                ua=lcua="";
        }

    }

    public String debugContext() {
        return "UA: " + ua + "\r\n" +
               "LCUA: " + lcua + "\r\n" +
               "TOKENS: " + debugList(tokens) + "\r\n" +
               "(OKEN): " + debugList(parenTokens);
    }
    private static String debugList(List<String> l) {
        if (l==null) return "<null>";
        if (l.size() < 1) return "";
        StringBuilder sb = new StringBuilder(l.size() * 15);
        sb.append("[ ");
        for (String s : l) {
            sb.append("\"").append(s.replace("\\", "\\\\").replace("\"","\\\"")).append("\", ");
        }
        return sb.substring(0,sb.length()-2) + "]";
    }
    private static String debugList(String[] l) {
        if (l == null) return "<null>";
        if (l.length < 1) return "";
        StringBuilder sb = new StringBuilder(l.length * 15);
        sb.append("[ ");
        for (String s : l) {
            sb.append("\"").append(s.replace("\\", "\\\\").replace("\"","\\\"")).append("\", ");
        }
        return sb.substring(0,sb.length()-2) + "]";
    }
    private static String debugList(Matcher[] l) {
        if (l == null) return "<null>";
        if (l.length < 1) return "";
        StringBuilder sb = new StringBuilder(l.length * 15);
        sb.append("{ ");
        for (Matcher s : l) {
            sb.append("\"").append(s.toString().replaceAll("\"","\\\"")).append("\", ");
        }
        return sb.substring(0,sb.length()-2) + "}";
    }

    private void addParenTokens(String tokens) {
        //System.out.println("paren token parsing: " + s);
        for (String s : tokens.split(";")) {
            String token = s.trim();
            if (token.length()>0) {
                if (token.matches("[0-9a-zA-Z\\.-]+/[0-9a-zA-Z\\.-]+(( )+[0-9a-zA-Z\\.-]+/[0-9a-zA-Z\\.-]+)+")) {
                    String[] subtokens = token.split(" ");
                    for (String ss : subtokens) {
                        String subtoken = ss.trim();
                        if (subtoken.length()>0)
                            parenTokens.add(subtoken);
                    }
                } else {
                    parenTokens.add(token);
                }
            }
        }
    }
    private String[]getAndConsumeTokens(Matcher[]match, List<String> _tokens, List<String> consumeTo) {
        if (DEBUG) System.out.println("getAndConsumeTokens " + debugList(tokens) + " matching " + debugList(match));
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
                    if (DEBUG) System.out.println("return " + debugList(res));
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


    /* Unit testing */
    public static void test() {
        UserAgentContext context = new UserAgentContext("a b c (d/3.3;e;f) g h i (j; k 2; l");
        String s;
        String[]ss;

        if (!context.getRegularTokens().equals("[ \"a\", \"b\", \"c\", \"g\", \"h\", \"i\"]")) throw new RuntimeException("Fail 1: " + context.getRegularTokens());
        if (!context.getParenTokens().equals("[ \"j\", \"k 2\", \"l\", \"d/3.3\", \"e\", \"f\"]")) throw new RuntimeException("Fail 2: " + context.getParenTokens());
        if (!String.valueOf(s=context.getcVersionAfterPattern("d/",MatchingType.BEGINS,MatchingRegion.REGULAR)).equals("null")) throw new RuntimeException("Fail 3: " + s);
        if (!String.valueOf(s=context.getcVersionAfterPattern("d/",MatchingType.BEGINS,MatchingRegion.PARENTHESIS)).equals("3.3")) throw new RuntimeException("Fail 4: " + s + " " + context.getDebug());
        if (!String.valueOf(s=context.getcVersionAfterPattern("d/",MatchingType.BEGINS,MatchingRegion.PARENTHESIS)).equals("null")) throw new RuntimeException("Fail 5: " + s);
        if (!context.getParenTokens().equals("[ \"j\", \"k 2\", \"l\", \"e\", \"f\"]")) throw new RuntimeException("Fail 6: " + context.getParenTokens());

        if (!Arrays.equals(ss=context.getcNextTokens(new Matcher[] {new Matcher("g",MatchingType.EQUALS),
            new Matcher("h",MatchingType.EQUALS)
        }, MatchingRegion.REGULAR),
        new String[] {"g","h"})) {
            throw new RuntimeException("Fail 7: " + debugList(ss) + " remains " + context.getRegularTokens());
        }
        if (!context.getRegularTokens().equals("[ \"a\", \"b\", \"c\", \"i\"]")) throw new RuntimeException("Fail 8: " + context.getRegularTokens());
        if (null != (ss=context.getcNextTokens(new Matcher[] {new Matcher("a",MatchingType.EQUALS),
            new Matcher("b",MatchingType.EQUALS),
            new Matcher("i",MatchingType.EQUALS)
        }, MatchingRegion.REGULAR))) {
            throw new RuntimeException("Fail 9: " + debugList(ss) + " remains " + context.getRegularTokens());
        }
        if (!context.getRegularTokens().equals("[ \"a\", \"b\", \"c\", \"i\"]")) throw new RuntimeException("Fail 9: " + context.getRegularTokens());
        if (null != (ss=context.getcNextTokens(new Matcher[] {new Matcher("c",MatchingType.EQUALS),
            new Matcher("i",MatchingType.EQUALS),
            new Matcher("i",MatchingType.EQUALS)
        }, MatchingRegion.REGULAR))) {
            throw new RuntimeException("Fail 10: " + debugList(ss) + " remains " + context.getRegularTokens());
        }
        if (!context.getRegularTokens().equals("[ \"a\", \"b\", \"c\", \"i\"]")) throw new RuntimeException("Fail 11: " + context.getRegularTokens());


        context = new UserAgentContext("Mozilla/5.0 (Linux; U; Android 4.0.4; fr-fr; GT-I9300-ORANGE/I9300BVBLH2 Build/IMM76D) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30");
        if (!context.getRegularTokens().equals("[ \"Mozilla/5.0\", \"AppleWebKit/534.30\", \"Version/4.0\", \"Mobile\", \"Safari/534.30\"]")) throw new RuntimeException("Fail 12: " + context.getRegularTokens());
        if (!context.getParenTokens().equals("[ \"KHTML, like Gecko\", \"Linux\", \"U\", \"Android 4.0.4\", \"fr-fr\", \"GT-I9300-ORANGE/I9300BVBLH2\", \"Build/IMM76D\"]")) throw new RuntimeException("Fail 13: " + context.getParenTokens());

        context = new UserAgentContext("Mozilla/5.0");
        if (!(s=context.getcRegion("Mozilla/([0-9\\.]+)", MatchingRegion.REGULAR, 1)).equals("5.0")) throw new RuntimeException("Fail 14: " + s);
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

    public String getcRegion(String pattern, MatchingRegion region, int group) {
        Matcher matcher = new Matcher(pattern, MatchingType.REGEXP);
        String token = getAndConsumeToken(matcher, region, consumedTokens);
        if (token == null) return null;
        java.util.regex.Pattern rpattern = java.util.regex.Pattern.compile(pattern);
        java.util.regex.Matcher rmatcher = rpattern.matcher(token);
        if (rmatcher.find())
            return rmatcher.group(group);
        else
            return null;
    }

    // Gets and consumes a token if found. Returns the version number after the pattern inside the token
    public String getcVersionAfterPattern(String pattern, MatchingType match, MatchingRegion region) {
        Matcher matcher = new Matcher(pattern, match);
        String token = getAndConsumeToken(matcher, region, consumedTokens);
        if (token == null) return null;
        return UserAgentDetectionHelper.getVersionNumber(token,matcher.getMatchType().endOfMatchPosition(token, pattern));
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

    public void consumeAllTokens() {
        while (null != getAndConsumeToken(new Matcher("",MatchingType.ALWAYS_MATCH), MatchingRegion.BOTH, consumedTokens));
    }

    public String getUA() {
        return ua;
    }
    public String getDebug() {
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
            sb.append("\"").append(s.replace("\\", "\\\\").replace("\"","\\\"")).append("\", ");
        }
        for (String s : parenTokens) {
            sb.append("\"").append(s.replace("\\", "\\\\").replace("\"","\\\"")).append("\", ");
        }
        return sb.substring(0,sb.length()-2) + "}";
    }

    public String getIgnoredTokens() {
        return debugList(ignoredTokens);
    }

    public String getConsumedTokens() {
        return debugList(consumedTokens);
    }
    public String getRegularTokens() {
        return debugList(tokens);
    }
    public Iterator<String> getRegularTokensIterator() {
        return tokens.iterator();
    }
    public Iterator<String> getParenTokensIterator() {
        return parenTokens.iterator();
    }
    public String getParenTokens() {
        return debugList(parenTokens);
    }
}