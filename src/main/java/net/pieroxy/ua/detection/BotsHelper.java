package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
class BotsHelper {

    public static String[] getGroups(String regexp, String ua, int ... groups) {
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(regexp);
        java.util.regex.Matcher m = pattern.matcher(ua);

        if (m.matches()) {
            String[]res = new String[groups.length];
            for (int i=0 ; i<groups.length ; i++) {
                res[i] = m.group(groups[i]);
            }
            return res;
        }
        return null;

    }

    static private Set<String> hiddenBots;
    static private Map<String, Bot> genericBotsBrandAndType;
    static private Map<String, Bot> genericBotsLiteral;
    static private Bot genericBotBase = new Bot(Brand.OTHER, BotFamily.ROBOT, "", "");
    static private GenericBot[]genericBotsPatterns = new GenericBot[] {
        new GenericBot("Mozilla/5\\.0 \\(compatible; ?([^\\);/]+)/([0-9\\.]+[a-z]?); ?(MirrorDetector; )?(\\+? ?https?://[^\\)]+)\\)( AppleWebKit/[0-9\\.]+)?(/[0-9\\.]+[a-z]?)?(/\\*)?", new int[]{1,2,4}, true),
        new GenericBot("Mozilla/5\\.0 \\(compatible; ([^\\);/]+)\\-([0-9\\.]+); (\\+? ?https?://[^\\)]+)\\)", new int[]{1,2,3}, true),
        new GenericBot("Mozilla/5\\.0 \\(compatible; ([^\\);/]+);? (\\+? ?https?://[^\\)]+)\\)", new int[]{1,0,2}, true),
        new GenericBot("([^\\(\\);/]+)/([0-9RC\\.]+) \\((\\+?https?://[^\\);]+)\\)( .*)?", new int[]{1,2,3}, true),
        new GenericBot("([^\\(\\);]+) \\((\\+?https?://[^\\);]+)\\)( .*)?", new int[]{1,0,2}, true),
        new GenericBot("([^\\(\\);/]+)/([0-9RC\\.]+) \\(([A-Za-z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})\\)( .*)?", new int[]{1,2,0}, true),
        new GenericBot("([^<>\\(\\);]+) \\(([A-Za-z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})\\)", new int[]{1,0,0}, true),
    };
    private static Map<String, OS> mapCfNetworkOS;
    private static Map<String, String> mapCfNetworkArchitecture;

    static {
        hiddenBots = new HashSet<String>();
        hiddenBots.add("Mozilla/4.0 (compatible; MSIE8.0; Windows NT 6.0) .NET CLR 2.0.50727)");
        hiddenBots.add("Mozilla/0.6 Beta (Windows)");
        hiddenBots.add("Mozilla/0.91 Beta (Windows)");

        genericBotsLiteral = new HashMap<String, Bot>();
        genericBotsLiteral.put("AdnormCrawler www.adnorm.com/crawler", new Bot(Brand.OTHER, BotFamily.ROBOT, "AdnormCrawler", ""));

        genericBotsBrandAndType = new HashMap<String, Bot>();
        // Complicated
        genericBotsBrandAndType.put("YodaoBot", new Bot(Brand.NETEASE, BotFamily.CRAWLER, "Yodao Bot", ""));
        genericBotsBrandAndType.put("Exabot", new Bot(Brand.EXALEAD, BotFamily.CRAWLER, "Exalead crawler", ""));
        genericBotsBrandAndType.put("Baiduspider", new Bot(Brand.BAIDU, BotFamily.CRAWLER, "Baidu Web search", ""));

        // Other form
        genericBotsBrandAndType.put("bingbot", new Bot(Brand.MICROSOFT, BotFamily.CRAWLER, "Bing Bot", ""));

        // Cleaned up:
        genericBotsBrandAndType.put("CloudFlare-AlwaysOnline", new Bot(Brand.CLOUDFLARE, BotFamily.CRAWLER, "Always Online", ""));
        genericBotsBrandAndType.put("Cloudflare-AMP", new Bot(Brand.CLOUDFLARE, BotFamily.CRAWLER, "AMP Discovery Fetcher", ""));
        genericBotsBrandAndType.put("YodaoBot-Image", new Bot(Brand.NETEASE, BotFamily.CRAWLER, "Yodao Image Bot", ""));
        genericBotsBrandAndType.put("Googlebot", new Bot(Brand.GOOGLE, BotFamily.CRAWLER, "Google Bot", ""));
        genericBotsBrandAndType.put("Yahoo! Slurp", new Bot(Brand.YAHOO, BotFamily.CRAWLER, "Yahoo! Slurp", ""));
        genericBotsBrandAndType.put("YandexAntivirus", new Bot(Brand.YANDEX, BotFamily.CRAWLER, "Yandex Crawler", ""));
        genericBotsBrandAndType.put("YandexFavicons", new Bot(Brand.YANDEX, BotFamily.CRAWLER, "Yandex Crawler", ""));
        genericBotsBrandAndType.put("YandexMedia", new Bot(Brand.YANDEX, BotFamily.CRAWLER, "Yandex Crawler", ""));
        genericBotsBrandAndType.put("YandexImages", new Bot(Brand.YANDEX, BotFamily.CRAWLER, "Yandex Crawler", ""));
        genericBotsBrandAndType.put("YandexImageResizer", new Bot(Brand.YANDEX, BotFamily.CRAWLER, "Yandex Crawler", ""));
        genericBotsBrandAndType.put("YandexBot", new Bot(Brand.YANDEX, BotFamily.CRAWLER, "Yandex Crawler", ""));
        genericBotsBrandAndType.put("proximic", new Bot(Brand.OTHER, BotFamily.CRAWLER, "Proximic Crawler", ""));
        genericBotsBrandAndType.put("Speedy Spider", new Bot(Brand.ENTIREWEB, BotFamily.CRAWLER, "Speedy Spider", ""));
        genericBotsBrandAndType.put("yoozBot", new Bot(Brand.OTHER, BotFamily.CRAWLER, "Yooz Bot", ""));
        genericBotsBrandAndType.put("Lipperhey Link Explorer", new Bot(Brand.OTHER, BotFamily.ROBOT, "Lipperhey", ""));
        genericBotsBrandAndType.put("Lipperhey Site Explorer", new Bot(Brand.OTHER, BotFamily.ROBOT, "Lipperhey", ""));
        genericBotsBrandAndType.put("Lipperhey SEO Service", new Bot(Brand.OTHER, BotFamily.ROBOT, "Lipperhey", ""));
        genericBotsBrandAndType.put("Lipperhey-Kaus-Australis", new Bot(Brand.OTHER, BotFamily.ROBOT, "Lipperhey", ""));
        genericBotsBrandAndType.put("Exabot-Images", new Bot(Brand.EXALEAD, BotFamily.CRAWLER, "Exalead crawler", ""));
        genericBotsBrandAndType.put("MegaIndex.ru", new Bot(Brand.MEGAINDEX, BotFamily.ROBOT, "MegaIndex.ru crawler", ""));
        genericBotsBrandAndType.put("spbot", new Bot(Brand.ENTIREWEB, BotFamily.CRAWLER, "SEO Profiler", ""));
        genericBotsBrandAndType.put("WBSearchBot", new Bot(Brand.OTHER, BotFamily.CRAWLER, "Ware Bay Search Crawler", ""));
        genericBotsBrandAndType.put("BLEXBot", new Bot(Brand.OTHER, BotFamily.ROBOT, "BLEX Bot", ""));
        genericBotsBrandAndType.put("meanpathbot", new Bot(Brand.MEANPATH, BotFamily.ROBOT, "meanpath", ""));
        genericBotsBrandAndType.put("DuckDuckGo-Favicons-Bot", new Bot(Brand.DUCKDUCKGO, BotFamily.ROBOT, "Favicons bot", ""));
        genericBotsBrandAndType.put("DomainTunoCrawler", new Bot(Brand.OTHER, BotFamily.CRAWLER, "Domain Tuno Crawler", ""));
        genericBotsBrandAndType.put("SeznamBot", new Bot(Brand.SEZNAM, BotFamily.CRAWLER, "SeznamBot crawler", ""));
        genericBotsBrandAndType.put("AhrefsBot", new Bot(Brand.OTHER, BotFamily.CRAWLER, "AhrefsBot", ""));
        genericBotsBrandAndType.put("oBot", new Bot(Brand.IBM, BotFamily.ROBOT, "oBot", ""));
        genericBotsBrandAndType.put("Google Desktop", new Bot(Brand.GOOGLE, BotFamily.CRAWLER, "Google Desktop Bot", ""));
        genericBotsBrandAndType.put("Google-Adwords-Instant-Mobile", new Bot(Brand.GOOGLE, BotFamily.ROBOT, "Google Landing page inspection bot", ""));
        genericBotsBrandAndType.put("Google-Structured-Data-Testing-Tool", new Bot(Brand.GOOGLE, BotFamily.ROBOT, "Google Structured Data Testing Tool", ""));

        genericBotsBrandAndType.put("ltx71 -", new Bot(Brand.OTHER,BotFamily.ROBOT,"ltx71",""));
        genericBotsBrandAndType.put("masscan", new Bot(Brand.UNKNOWN,BotFamily.CRAWLER,"Mass IP port scanner",""));
        genericBotsBrandAndType.put("Baiduspider+", new Bot(Brand.BAIDU,BotFamily.CRAWLER,"Baidu Web search",""));
        genericBotsBrandAndType.put("FeedlyBot", new Bot(Brand.OTHER,BotFamily.FEED_CRAWLER,"Feedly",""));
        genericBotsBrandAndType.put("Y!J-ASR/0.1 crawler", new Bot(Brand.YAHOO,BotFamily.CRAWLER,"Yahoo Japan",""));
        genericBotsBrandAndType.put("CCBot", new Bot(Brand.OTHER,BotFamily.CRAWLER,"Common Crawl",""));

        mapCfNetworkOS = new HashMap<String, OS>();
        mapCfNetworkOS.put("1.1/", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.2"));
        mapCfNetworkOS.put("1.2.1/", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.3.2"));
        mapCfNetworkOS.put("1.2.2/", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.3.9"));
        mapCfNetworkOS.put("1.2.6/", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.3.9"));
        mapCfNetworkOS.put("128/8.0.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.4.0"));
        mapCfNetworkOS.put("128/8.1.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.4.1"));
        mapCfNetworkOS.put("128.2/8.2.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.4.2"));
        mapCfNetworkOS.put("129.5/8.3.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.4.3"));
        mapCfNetworkOS.put("129.9/8.4.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.4.4"));
        mapCfNetworkOS.put("129.9/8.5.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.4.5"));
        mapCfNetworkOS.put("129.10/8.4.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.4.4"));
        mapCfNetworkOS.put("129.10/8.5.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.4.5"));
        mapCfNetworkOS.put("129.13/8.6.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.4.6"));
        mapCfNetworkOS.put("129.16/8.7.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.4.7"));
        mapCfNetworkOS.put("129.18/8.8.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.4.8"));
        mapCfNetworkOS.put("129.20/8.9.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.4.9"));
        mapCfNetworkOS.put("129.21/8.10.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.4.10"));
        mapCfNetworkOS.put("129.22/8.11.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.4.11"));
        mapCfNetworkOS.put("217/9.0.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.5.0"));
        mapCfNetworkOS.put("220/9.1.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.5.1"));
        mapCfNetworkOS.put("221.2/9.2.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.5.2 dev"));
        mapCfNetworkOS.put("221.5/9.2.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.5.2"));
        mapCfNetworkOS.put("330/9.3.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.5.3"));
        mapCfNetworkOS.put("330.4/9.4.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.5.4"));
        mapCfNetworkOS.put("339.5/9.5.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.5.5"));
        mapCfNetworkOS.put("422.11/9.6.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.5.6"));
        mapCfNetworkOS.put("438.12/9.7.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.5.7"));
        mapCfNetworkOS.put("438.14/9.8.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.5.8"));
        mapCfNetworkOS.put("454.4/10.0.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.6.0"));
        mapCfNetworkOS.put("454.5/10.2.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.6.2"));
        mapCfNetworkOS.put("454.9.4/10.3.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.6.3"));
        mapCfNetworkOS.put("454.9.7/10.4.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.6.4"));
        mapCfNetworkOS.put("454.11.5/10.5.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.6.5"));
        mapCfNetworkOS.put("454.11.5/10.6.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.6.6"));
        mapCfNetworkOS.put("454.11.12/10.7.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.6.7"));
        mapCfNetworkOS.put("454.12.4/10.8.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.6.8"));
        mapCfNetworkOS.put("459/10.0.0d3", new OS(Brand.APPLE, OSFamily.IOS, "iOS", "3.1.3"));
        mapCfNetworkOS.put("485.2/10.3.1", new OS(Brand.APPLE, OSFamily.IOS, "iOS", "4"));
        mapCfNetworkOS.put("485.10.2/10.3.1", new OS(Brand.APPLE, OSFamily.IOS, "iOS", "4.1"));
        mapCfNetworkOS.put("485.12.7/10.4.0", new OS(Brand.APPLE, OSFamily.IOS, "iOS", "4.2.1"));
        mapCfNetworkOS.put("485.12.30/10.4.0", new OS(Brand.APPLE, OSFamily.IOS, "iOS", "4.2.8"));
        mapCfNetworkOS.put("485.13.9/11.0.0", new OS(Brand.APPLE, OSFamily.IOS, "iOS", "4.3.*"));
        mapCfNetworkOS.put("520.0.13/11.1.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.7.1"));
        mapCfNetworkOS.put("520.2.5/11.2.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.7.2"));
        mapCfNetworkOS.put("520.3.2/11.3.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.7.3"));
        mapCfNetworkOS.put("520.4.3/11.4.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.7.4"));
        mapCfNetworkOS.put("520.5.1/11.4.2", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.7.5"));
        mapCfNetworkOS.put("548.0.3/11.0.0", new OS(Brand.APPLE, OSFamily.IOS, "iOS", "5"));
        mapCfNetworkOS.put("548.0.4/11.0.0", new OS(Brand.APPLE, OSFamily.IOS, "iOS", "5.0.1"));
        mapCfNetworkOS.put("548.1.4/11.0.0", new OS(Brand.APPLE, OSFamily.IOS, "iOS", "5.1"));
        mapCfNetworkOS.put("596.0.1/12.0.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.8.0"));
        mapCfNetworkOS.put("596.1/12.1.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.8.1"));
        mapCfNetworkOS.put("596.2.3/12.2.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.8.2"));
        mapCfNetworkOS.put("596.3.3/12.3.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.8.3"));
        mapCfNetworkOS.put("596.4.3/12.4.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.8.4"));
        mapCfNetworkOS.put("596.5/12.5.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.8.5"));
        mapCfNetworkOS.put("596.6.2/12.5.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.8.5"));
        mapCfNetworkOS.put("602/13.0.0", new OS(Brand.APPLE, OSFamily.IOS, "iOS", "6.0-b3"));
        mapCfNetworkOS.put("609/13.0.0", new OS(Brand.APPLE, OSFamily.IOS, "iOS", "6.0.*"));
        mapCfNetworkOS.put("609.1.4/13.0.0", new OS(Brand.APPLE, OSFamily.IOS, "iOS", "6.1.*"));
        mapCfNetworkOS.put("672.0.2/14.0.0", new OS(Brand.APPLE, OSFamily.IOS, "iOS", "7.0.0-2"));
        mapCfNetworkOS.put("672.0.8/14.0.0", new OS(Brand.APPLE, OSFamily.IOS, "iOS", "7.0.3-6"));
        mapCfNetworkOS.put("672.1.12/14.0.0", new OS(Brand.APPLE, OSFamily.IOS, "iOS", "7.1-b5"));
        mapCfNetworkOS.put("672.1.13/13.3.0", new OS(Brand.APPLE, OSFamily.IOS, "iOS", "7.1"));
        mapCfNetworkOS.put("672.1.13/14.0.0", new OS(Brand.APPLE, OSFamily.IOS, "iOS", "7.1"));
        mapCfNetworkOS.put("672.1.14/14.0.0", new OS(Brand.APPLE, OSFamily.IOS, "iOS", "7.1.1"));
        mapCfNetworkOS.put("672.1.15/14.0.0", new OS(Brand.APPLE, OSFamily.IOS, "iOS", "7.1.2"));
        mapCfNetworkOS.put("673.0.3/13.0.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.9.0"));
        mapCfNetworkOS.put("673.0.3/13.0.2", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.9.1"));
        mapCfNetworkOS.put("673.2.1/13.1.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.9.2"));
        mapCfNetworkOS.put("673.3/13.2.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.9.3 beta"));
        mapCfNetworkOS.put("673.3/13.3.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.9.3 beta"));
        mapCfNetworkOS.put("673.3/13.4.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.9.3 beta"));
        mapCfNetworkOS.put("673.4/13.2.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.9.3"));
        mapCfNetworkOS.put("673.4/13.3.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.9.4"));
        mapCfNetworkOS.put("673.4/13.4.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.9.5"));
        mapCfNetworkOS.put("673.5/13.4.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.9.*"));
        mapCfNetworkOS.put("696.0.2/14.0.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.10.0"));
        mapCfNetworkOS.put("699/14.0.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.10.0"));
        mapCfNetworkOS.put("703.1/14.0.0", new OS(Brand.APPLE, OSFamily.IOS, "iOS", "7.0"));
        mapCfNetworkOS.put("703.1.6/14.0.0", new OS(Brand.APPLE, OSFamily.IOS, "iOS", "8.0"));
        mapCfNetworkOS.put("708.1/14.0.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.10.0"));
        mapCfNetworkOS.put("709.1/14.0.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.10.0"));
        mapCfNetworkOS.put("707/14.0.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.10.0"));
        mapCfNetworkOS.put("709/14.0.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.10.0"));
        mapCfNetworkOS.put("711.0.6/14.0.0", new OS(Brand.APPLE, OSFamily.IOS, "iOS", "8.0.0-2"));
        mapCfNetworkOS.put("711.1.12/14.0.0", new OS(Brand.APPLE, OSFamily.IOS, "iOS", "8.1.0"));
        mapCfNetworkOS.put("711.1.16/14.0.0", new OS(Brand.APPLE, OSFamily.IOS, "iOS", "8.1.1-3"));
        mapCfNetworkOS.put("714/14.0.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.10.0"));
        mapCfNetworkOS.put("718/14.0.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.10.0"));
        mapCfNetworkOS.put("720.0.4/14.0.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.10.0"));
        mapCfNetworkOS.put("720.0.7/14.0.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.10.0"));
        mapCfNetworkOS.put("720.0.8/14.0.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.10.0"));
        mapCfNetworkOS.put("720.0.9/14.0.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.10.0"));
        mapCfNetworkOS.put("720.1.1/14.0.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.10.1"));
        mapCfNetworkOS.put("720.2.2/14.1.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.10.2"));
        mapCfNetworkOS.put("720.2.3/14.1.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.10.1"));
        mapCfNetworkOS.put("720.2.4/14.1.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.10.2"));
        mapCfNetworkOS.put("720.3.6/14.3.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.10.3"));
        mapCfNetworkOS.put("720.3.9/14.3.0", new OS(Brand.APPLE, OSFamily.MACOSX, "MacOSX", "10.10.3"));

        mapCfNetworkArchitecture = new HashMap<String, String>();
        mapCfNetworkArchitecture.put("128/8.0.0", "PowerPC");
        mapCfNetworkArchitecture.put("128/8.1.0", "PowerPC");
        mapCfNetworkArchitecture.put("128.2/8.2.0", "PowerPC");
        mapCfNetworkArchitecture.put("129.5/8.3.0", "PowerPC");
        mapCfNetworkArchitecture.put("129.9/8.4.0", "PowerPC");
        mapCfNetworkArchitecture.put("129.9/8.5.0", "PowerPC");
        mapCfNetworkArchitecture.put("129.10/8.4.0", "Intel");
        mapCfNetworkArchitecture.put("129.10/8.5.0", "Intel");
    }

    static String getAndConsumeUrl(UserAgentContext context, MatchingRegion region, String pattern) {
        String url = sanitizeUrl(context.getcToken(pattern, MatchingType.CONTAINS, region));
        return url;
    }

    static String sanitizeUrl(String url) {
        if (url==null) url="";
        if (url.startsWith("+http")) url = url.substring(1);
        if (url.startsWith("+ http")) url = url.substring(2);
        if (url.endsWith(";")) url = url.substring(0, url.length()-1);
        if (url.contains("; ")) url = url.substring(0, url.indexOf("; "));
        if (url.contains(", ")) url = url.substring(0, url.indexOf(", "));
        return url.trim();
    }

    static String consumeUrlAndMozilla(UserAgentContext context, String url) {
        UserAgentDetectionHelper.consumeMozilla(context);
        return getAndConsumeUrl(context, MatchingRegion.PARENTHESIS, url);
    }

    static Bot getGenericBots(String userAgent, UserAgentContext context) {
        for (Map.Entry<String, Bot> e : genericBotsLiteral.entrySet()) {
            if (userAgent.equals(e.getKey())) {
                context.consumeAllTokens();
                return e.getValue();
            }
        }

        for (GenericBot gb : genericBotsPatterns) {
            Bot b = getGenericBot(gb, userAgent);
            if (b!=null) {
                if (gb.discardAll) context.consumeAllTokens();
                return b;
            }
        }
        return null;
    }
    static Bot getGenericBot(GenericBot gb, String userAgent) {
        java.util.regex.Matcher m = gb.pattern.matcher(userAgent);

        if (m.matches() && !userAgent.startsWith("Curl/PHP")) {
            String botName = m.group(gb.groups[0]);
            Bot baseBot = genericBotsBrandAndType.get(botName);
            String description = baseBot == null ? botName : baseBot.getDescription();
            if (baseBot == null) baseBot = genericBotBase;
            String version = gb.groups[1] == 0 ? "" : m.group(gb.groups[1]);
            String url = gb.groups[2] == 0 ? "" : m.group(gb.groups[2]);
            return new Bot(baseBot.getVendor(), baseBot.getFamily(), description, version, sanitizeUrl(url));
        }
        return null;
    }

    public static Bot getBot(UserAgentContext context) {
        int pos=0;
        String ver;
        String[]multi;

        Bot b = getGenericBots(context.getUA(), context) ;
        if (b != null) {
            return b;
        }

        if (hiddenBots.contains(context.getUA())) {
            context.consumeAllTokens();
            return new Bot(Brand.UNKNOWN,BotFamily.HIDDEN_BOT,"","");
        } else if (context.consume("commoncrawl.org/research//", MatchingType.BEGINS, MatchingRegion.REGULAR)) {
            ver = context.getcVersionAfterPattern("CCResearchBot/", MatchingType.BEGINS,MatchingRegion.BOTH);
            if (ver == null) ver="";

            return new Bot(Brand.OTHER,BotFamily.CRAWLER,"Common Crawl",ver , "http://commoncrawl.org/faqs/");
        } else if (context.getUA().equals("Qwantify/1.0")) {
            context.consumeAllTokens();
            return new Bot(Brand.QWANT,BotFamily.CRAWLER,"Qwant crawler","1.0");
        } else if (context.consume("via ggpht.com GoogleImageProxy", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) { // http://serverfault.com/questions/581857/apache-logs-flooded-with-connections-via-ggpht-com-googleimageproxy.
            return new Bot(Brand.GOOGLE,BotFamily.ROBOT,"Gmail image downloader proxy","");
        } else if (context.consume("Google-StructuredDataTestingTool", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            return new Bot(Brand.GOOGLE,BotFamily.ROBOT,"Google Structured Data Testing Tool",consumeUrlAndMozilla(context, "+http://"));
        } else if (context.consume("ONDOWN3.2", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) { // Looks like a bot to me.
            return new Bot(Brand.UNKNOWN,BotFamily.ROBOT,"ONDOWN","3.2");
        } else if (context.consume("Google Web Preview", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            context.consume("generic", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume("iPhone", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            return new Bot(Brand.GOOGLE, BotFamily.ROBOT,"Web Preview","");
        } else if ((multi = context.getcNextTokens(new Matcher[] {new Matcher("BusinessBot:", MatchingType.EQUALS),
            new Matcher("^[A-Za-z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", MatchingType.REGEXP)
        },
        MatchingRegion.REGULAR)) != null) {
            return new Bot(Brand.OTHER, BotFamily.ROBOT,"BusinessBot","", "");
        }
        else if (context.consume("Contact: backend@getprismatic.com", MatchingType.EQUALS, MatchingRegion.PARENTHESIS) ||
        (multi = context.getcNextTokens(new Matcher[] {new Matcher("Contact:", MatchingType.EQUALS),
            new Matcher("feedback@getprismatic.com", MatchingType.EQUALS)
        },
        MatchingRegion.REGULAR)) != null) {
            return new Bot(Brand.OTHER, BotFamily.ROBOT,"Get Prismatic Bot","", "http://getprismatic.com/");
        }
        else if ((ver=context.getcVersionAfterPattern("Diffbot/", MatchingType.BEGINS,MatchingRegion.BOTH))!=null ||
                 (ver=context.getcVersionAfterPattern("diffbot/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null ||
                 context.contains("+http://www.diffbot.com", MatchingType.BEGINS,MatchingRegion.PARENTHESIS))  {
            return new Bot(Brand.OTHER, BotFamily.ROBOT,"Diffbot ", ver==null?"":ver, consumeUrlAndMozilla(context, "http://"));
        } else if ((ver=context.getcVersionAfterPattern("GWPImages/", MatchingType.BEGINS,MatchingRegion.PARENTHESIS))!=null)  {
            return new Bot(Brand.OTHER, BotFamily.ROBOT,"GWPImages ", ver, consumeUrlAndMozilla(context, "http://"));
        } else if ((ver=context.getcVersionAfterPattern("LSSRocketCrawler/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null)  {
            context.consume("LightspeedSystems", MatchingType.EQUALS, MatchingRegion.REGULAR);
            return new Bot(Brand.OTHER, BotFamily.ROBOT,"LSSRocketCrawler ", ver);
        } else if ((ver=context.getcVersionAfterPattern("OrangeBot/", MatchingType.BEGINS,MatchingRegion.PARENTHESIS))!=null)  {
            context.consume("[0-9a-zA-Z\\.]+@[0-9a-zA-Z\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
            return new Bot(Brand.ORANGE, BotFamily.CRAWLER,"Orange Bot ", ver, consumeUrlAndMozilla(context, "http://"));
        } else if ((ver=context.getcVersionAfterPattern("del.icio.us-thumbnails/", MatchingType.BEGINS,MatchingRegion.BOTH))!=null)  {
            return new Bot(Brand.DELICIOUS, BotFamily.ROBOT,"Thumbnails crawler ", ver);
        } else if ((ver=context.getcVersionAfterPattern("EvoHtmlToPdf/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
            return new Bot(Brand.OTHER,BotFamily.ROBOT,"EvoHtmlToPdf",ver);
        } else if ((ver=context.getcVersionAfterPattern("PhantomJS/", MatchingType.BEGINS,MatchingRegion.REGULAR,2))!=null) {
            if (context.consume("development", MatchingType.EQUALS,MatchingRegion.PARENTHESIS)) {
                ver += " dev";
            }
            context.consume("Unknown", MatchingType.EQUALS,MatchingRegion.PARENTHESIS);
            return new Bot(Brand.OPENSOURCE_COMMUNITY,BotFamily.ROBOT,"PhantomJS", ver);
        } else if (context.consume("theoldreader.com", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            context.consume("feed-id=", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            context.consume("[0-9]+ subscribers", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
            consumeUrlAndMozilla(context, "http://");
            return new Bot(Brand.GOOGLE,BotFamily.FEED_CRAWLER,"RSS Feed Fetcher","","http://theoldreader.com/");
        } else if (context.consume("Feedfetcher-Google;", MatchingType.EQUALS, MatchingRegion.REGULAR)) {
            context.consume("feed-id=", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            context.consume("[0-9]+ subscribers", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
            return new Bot(Brand.GOOGLE,BotFamily.FEED_CRAWLER,"RSS Feed Fetcher","", getAndConsumeUrl(context, MatchingRegion.PARENTHESIS, "+http://www.google"));
        } else if (context.consume("Porkbun/Mustache", MatchingType.EQUALS, MatchingRegion.REGULAR)) {
            context.consume(".*@porkbun.com", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
            context.consume("Website Analysis", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            return new Bot(Brand.OTHER,BotFamily.ROBOT,"Porkbun Website Analysis","", getAndConsumeUrl(context, MatchingRegion.PARENTHESIS, "http://"));
        } else if (context.consume("yacybot", MatchingType.EQUALS, MatchingRegion.REGULAR)) {
            context.consume("freeworld/global", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume("yacy.net", MatchingType.EQUALS, MatchingRegion.REGULAR);
            return new Bot(Brand.YACI,BotFamily.CRAWLER,"Yacy bot","", getAndConsumeUrl(context, MatchingRegion.REGULAR, "http://"));
        } else if (context.consume("125LA", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) { // Will look for login forms and upload forms
            context.consume("Mozilla/4.0", MatchingType.EQUALS, MatchingRegion.REGULAR);
            context.consume("compatible", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume("MSIE 9.0", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            return new Bot(Brand.OTHER,BotFamily.SPAMBOT,"Unknown bot","");
        } else if ((ver = context.getcVersionAfterPattern("AvantGo ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            context.consume("Mozilla/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            return new Bot(Brand.OTHER,BotFamily.ROBOT,"AvantGo", ver);
        } else if ((ver = context.getcVersionAfterPattern("InfegyAtlas/",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            context.consume("Linux", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            consumeUrlAndMozilla(context, "@");
            return new Bot(Brand.OTHER,BotFamily.ROBOT,"InfegyAtlas", ver, "http://infegy.com");
        } else if ((ver = context.getcVersionAfterPattern("Twitterbot/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            return new Bot(Brand.UNKNOWN,BotFamily.ROBOT,"Twitterbot", ver);
        } else if ((ver = context.getcVersionAfterPattern("BingPreview/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            return new Bot(Brand.MICROSOFT,BotFamily.ROBOT,"Bing Web Preview", ver);
        } else if ((ver = context.getcVersionAfterPattern("LinkScan/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            return new Bot(Brand.ELSOP,BotFamily.ROBOT,"LinkScan", ver);
        } else if ((ver = context.getcVersionAfterPattern("Fever/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            context.consume("Allow like Gecko",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume("Feed Parser",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            return new Bot(Brand.UNKNOWN,BotFamily.FEED_CRAWLER,"Feed A Fever", ver, getAndConsumeUrl(context, MatchingRegion.PARENTHESIS, "http://"));
        } else if (context.consume("NetShelter ContentScan(, contact [a-zA-Z0-9\\.]+@[a-zA-Z0-9\\.]+ for information)?",  MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) {
            return new Bot(Brand.UNKNOWN,BotFamily.ROBOT,"NetShelter ContentScan", "");
        } else if ((ver = context.getcVersionAfterPattern("SimplePie/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            context.consume("Build/",  MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("Allow like Gecko",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume("Feed Parser",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            return new Bot(Brand.UNKNOWN,BotFamily.FEED_CRAWLER,"SimplePie", ver, getAndConsumeUrl(context, MatchingRegion.PARENTHESIS, "http://"));
        } else if ((ver = context.getcVersionAfterPattern("Qwantify/",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            return new Bot(Brand.OTHER,BotFamily.ROBOT,"Qwantify Crawler", ver, consumeUrlAndMozilla(context, "https://"));
        } else if ((ver = context.getcVersionAfterPattern("PageAnalyzer/",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            return new Bot(Brand.UNKNOWN,BotFamily.CRAWLER,"PageAnalyzer", ver, consumeUrlAndMozilla(context, "http://"));
        } else if ((ver = context.getcVersionAfterPattern("Pagespeed/",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            return new Bot(Brand.UNKNOWN,BotFamily.ROBOT,"Pagespeed feed fetcher", ver, consumeUrlAndMozilla(context, "http://"));
        } else if ((ver = context.getcVersionAfterPattern("ClearBot/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            return new Bot(Brand.CLEARSWIFT,BotFamily.ROBOT,"ClearBot crawler", ver, getAndConsumeUrl(context, MatchingRegion.PARENTHESIS, "http://"));
        } else if ((ver = context.getcVersionAfterPattern("Mail.RU_Bot/",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            return new Bot(Brand.MAILRU,BotFamily.CRAWLER,"Mail.ru crawler", ver, consumeUrlAndMozilla(context, "http://go.mail.ru"));
        } else if ((ver = context.getcVersionAfterPattern("MJ12bot/",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            return new Bot(Brand.MAJESTIC12,BotFamily.CRAWLER,"Majestic 12", ver, consumeUrlAndMozilla(context, "http://"));
        } else if ((ver = context.getcVersionAfterPattern("GigablastOpenSource/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            return new Bot(Brand.OTHER,BotFamily.CRAWLER,"GigaBlast Crawler", ver);
        } else if (context.getUA().equals("NetLyzer FastProbe")) {
            context.consumeAllTokens();
            return new Bot(Brand.OTHER,BotFamily.ROBOT,"NetLyzer FastProbe", "");
        } else if (context.getUA().equals("NerdyBot")) {
            context.consumeAllTokens();
            return new Bot(Brand.OTHER,BotFamily.ROBOT,"Nerdy Bot", "", "http://nerdybot.com");
        } else if (context.getUA().equals("PHPCrawl")) {
            context.consumeAllTokens();
            return new Bot(Brand.OPENSOURCE_COMMUNITY,BotFamily.ROBOT,"PHP Crawl", "", "http://phpcrawl.cuab.de");
        } else if (context.getUA().equals("updown_tester")) {
            context.consume("updown_tester", MatchingType.EQUALS, MatchingRegion.REGULAR);
            return new Bot(Brand.UNKNOWN,BotFamily.ROBOT,"Unknown (updown_tester)", "");
        } else if (context.getUA().equals("YisouSpider")) {
            context.consume("YisouSpider", MatchingType.EQUALS, MatchingRegion.REGULAR);
            return new Bot(Brand.UNKNOWN,BotFamily.ROBOT,"YisouSpider", "");
        } else if (context.getUA().equals("RSSGraffiti")) {
            context.consume("RSSGraffiti", MatchingType.EQUALS, MatchingRegion.REGULAR);
            return new Bot(Brand.SCRIBBLE,BotFamily.ROBOT,"RSS Graffiti", "");
        } else if (context.getUA().startsWith("WordPress/")) {
            ver = context.getcVersionAfterPattern("WordPress/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            return new Bot(Brand.OTHER, BotFamily.ROBOT, "WordPress", ver, getAndConsumeUrl(context, MatchingRegion.REGULAR, "http://"));
        } else if (context.getUA().contains("TuringOS; Turing Machine")) {
            // No idea. This thing only hit a few URLs and doesn't render them (no JS/CSS/IMGs)...
            context.consumeAllTokens();
            return new Bot(Brand.OTHER, BotFamily.ROBOT, "Turing", "");
        } else if (context.getUA().indexOf("<a href=\"")>-1 && context.getUA().endsWith("</a> (Windows NT 5.1; U; en) Presto/2.10.229 Version/11.60")) {
            context.consumeAllTokens();
            return new Bot(Brand.UNKNOWN, BotFamily.SPAMBOT, "Link reference bombing", "");
        } else if (context.getLCUA().matches(".*<script>((window|document|top)\\.)?location(\\.href)?=.*")) {
            context.consumeAllTokens();
            return new Bot(Brand.UNKNOWN, BotFamily.SPAMBOT, "Infected site honeypot", "");
        } else if ((multi = context.getcNextTokens(new Matcher[] {new Matcher("Go", MatchingType.EQUALS),
            new Matcher("[0-9\\.]+", MatchingType.REGEXP),
            new Matcher("package", MatchingType.EQUALS),
            new Matcher("http", MatchingType.EQUALS)
        },
        MatchingRegion.REGULAR)) != null) {
            return new Bot(Brand.UNKNOWN, BotFamily.ROBOT, "Go lang", multi[1], "https://golang.org/src/net/http/requestwrite_test.go");
        }
        else if ((multi = context.getcNextTokens(new Matcher[] {new Matcher("Cloud", MatchingType.EQUALS), // ", "", ".", "Contact", "research@pdrlabs.net
                 new Matcher("mapping", MatchingType.EQUALS),
                 new Matcher("experiment.", MatchingType.EQUALS),
                 new Matcher("Contact", MatchingType.EQUALS),
                 new Matcher("research@pdrlabs.net", MatchingType.EQUALS)
        },
        MatchingRegion.REGULAR)) != null) {
            return new Bot(Brand.UNKNOWN, BotFamily.ROBOT, "Cloud Mapping Experiment by pdrlabs.net", "", "http://pdrlabs.net");
        }
        else if ((multi = context.getcNextTokens(new Matcher[] {new Matcher("bot", MatchingType.EQUALS),
                 new Matcher("http://", MatchingType.EQUALS),
                 new Matcher("bot@bot\\.(com|bot)", MatchingType.REGEXP)
        },
        MatchingRegion.PARENTHESIS)) != null) {
            return new Bot(Brand.UNKNOWN, BotFamily.ROBOT, "", "", multi[1]);
        }
        else if (context.consume("Edition Yx",MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
            // See http://www.spambotsecurity.com/forum/viewtopic.php?f=7&t=1470
            // My own logs report the same behavior.
            return new Bot(Brand.UNKNOWN, BotFamily.SPAMBOT, "Edition Yx", "");

        } else if ((ver=context.getcVersionAfterPattern("Gnomit/",MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            return new Bot(Brand.OTHER, BotFamily.ROBOT, "Gnomit crawler", ver);

        } else if ((ver=context.getcVersionAfterPattern("SurveyBot/",MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            context.consume("DomainTools", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            return new Bot(Brand.DOMAINTOOLS, BotFamily.ROBOT, "SurveyBot", ver);

        } else if (context.getLCUA().indexOf("<a href=\"")>-1 || context.getLCUA().indexOf("<a href=\'")>-1) {
            context.consumeAllTokens();
            return new Bot(Brand.UNKNOWN, BotFamily.SPAMBOT, "Link reference bombing", "");

            // DAUM bots
        } else if ((ver=context.getcVersionAfterPattern("DAUMOA ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null ||
                   (ver=context.getcVersionAfterPattern("DAUMOA/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null)  {
            context.consume("MSIE ", MatchingType.BEGINS,MatchingRegion.PARENTHESIS);
            context.consume("DAUM Web Robot", MatchingType.EQUALS,MatchingRegion.PARENTHESIS);
            context.consume("Daum Communications", MatchingType.BEGINS,MatchingRegion.PARENTHESIS);
            return new Bot(Brand.DAUM, BotFamily.CRAWLER,"Daum Web Search", ver, consumeUrlAndMozilla(context, "http://"));
        } else if ((ver=context.getcVersionAfterPattern("Daumoa-feedfetcher/", MatchingType.BEGINS, MatchingRegion.REGULAR))!=null)  {
            while (context.consume(".* compatible", MatchingType.REGEXP,MatchingRegion.PARENTHESIS));
            context.consume("not on", MatchingType.BEGINS,MatchingRegion.PARENTHESIS);
            context.consume("not on", MatchingType.BEGINS,MatchingRegion.PARENTHESIS);
            return new Bot(Brand.DAUM, BotFamily.FEED_CRAWLER,"Daum Feed Fetcher", ver, consumeUrlAndMozilla(context, "http://"));
        } else if (context.consume("DAUMOA-video", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))  {
            return new Bot(Brand.DAUM, BotFamily.CRAWLER,"Daum Video Search", "", consumeUrlAndMozilla(context, "http://"));
        } else if ((ver=context.getcVersionAfterPattern("Daumoa/", MatchingType.BEGINS, MatchingRegion.REGULAR))!=null)  {
            context.consume("MSIE or Firefox", MatchingType.BEGINS,MatchingRegion.PARENTHESIS);
            context.consume("Firefox or MSIE", MatchingType.BEGINS,MatchingRegion.PARENTHESIS);
            context.consume("not on", MatchingType.BEGINS,MatchingRegion.PARENTHESIS);
            return new Bot(Brand.DAUM, BotFamily.CRAWLER,"Daum Web Search", ver, consumeUrlAndMozilla(context, "http://"));

            // FB BOTS
        } else if ((ver = context.getcVersionAfterPattern("visionutils/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            return new Bot(Brand.FACEBOOK, BotFamily.ROBOT, "Facebook image fetcher", ver);
        } else if ((ver=context.getcVersionAfterPattern("facebookexternalhit/",MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            return new Bot(Brand.FACEBOOK, BotFamily.CRAWLER, "Facebook image fetcher", ver, getAndConsumeUrl(context, MatchingRegion.PARENTHESIS, "http://"));
            // GOOGLE BOTS
        } else if ((multi = context.getcNextTokens(new Matcher[] {new Matcher("Google", MatchingType.EQUALS),
            new Matcher("favicon", MatchingType.EQUALS)
        },
        MatchingRegion.REGULAR)) != null) {
            return new Bot(Brand.GOOGLE, BotFamily.ROBOT, "Google favicon", "");
        }
        else if ((pos=context.getUA().indexOf("Googlebot-News"))>-1) {
            return new Bot(Brand.GOOGLE, BotFamily.CRAWLER, "Google News bot", UserAgentDetectionHelper.getVersionNumber(context.getUA(),pos+15));
        } else if ((ver=context.getcVersionAfterPattern("Googlebot-Image/",MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            return new Bot(Brand.GOOGLE, BotFamily.CRAWLER, "Google Image Bot", ver, getAndConsumeUrl(context, MatchingRegion.PARENTHESIS, "http://"));
        } else if ((ver=context.getcVersionAfterPattern("Googlebot-Video/",MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            return new Bot(Brand.GOOGLE, BotFamily.CRAWLER, "Google Video Bot", ver, getAndConsumeUrl(context, MatchingRegion.PARENTHESIS, "http://"));
        } else if ((ver=context.getcVersionAfterPattern("Googlebot-Mobile/",MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            context.consume("DoCoMo/2.0", MatchingType.EQUALS, MatchingRegion.REGULAR);
            context.consume("N905i", MatchingType.EQUALS, MatchingRegion.REGULAR);
            context.consume("compatible", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume("TB", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume("c100", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume("W24H16", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            return new Bot(Brand.GOOGLE, BotFamily.CRAWLER, "Google Mobile Bot", ver, getAndConsumeUrl(context, MatchingRegion.PARENTHESIS, "http://"));
        } else if ((ver=context.getcVersionAfterPattern("Mediapartners-Googlebot",MatchingType.BEGINS, MatchingRegion.BOTH))!=null) {
            return new Bot(Brand.GOOGLE, BotFamily.CRAWLER, "Google Adsense Bot", ver, getAndConsumeUrl(context, MatchingRegion.PARENTHESIS, "http://"));
        } else if ((ver=context.getcVersionAfterPattern("Mediapartners-Google",MatchingType.BEGINS, MatchingRegion.BOTH))!=null) {
            return new Bot(Brand.GOOGLE, BotFamily.CRAWLER, "Google Adsense Bot", ver, getAndConsumeUrl(context, MatchingRegion.PARENTHESIS, "http://"));
        } else if ((ver=context.getcVersionAfterPattern("AdsBot-Google-",MatchingType.BEGINS, MatchingRegion.REGULAR))!=null ||
                   context.consume("AdsBot-Google",MatchingType.BEGINS, MatchingRegion.REGULAR)) {
            return new Bot(Brand.GOOGLE, BotFamily.CRAWLER, "Google Adsense Bot", ver, getAndConsumeUrl(context, MatchingRegion.PARENTHESIS, "http://"));
        } else if (context.consume("Google Desktop",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            context.consume("compatible", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume("Mozilla/5.0", MatchingType.EQUALS, MatchingRegion.REGULAR);
            return new Bot(Brand.GOOGLE, BotFamily.CRAWLER, "Google Desktop Bot", "", getAndConsumeUrl(context, MatchingRegion.PARENTHESIS, "http://"));
        } else if ((multi = context.getcNextTokens(new Matcher[] {new Matcher("Googlebot", MatchingType.EQUALS),
            new Matcher("[0-9\\.]+", MatchingType.REGEXP)
        },
        MatchingRegion.REGULAR)) != null) {
            return new Bot(Brand.GOOGLE, BotFamily.CRAWLER, "Google Bot", multi[1]);
        }
        else if ((ver=context.getcVersionAfterPattern("Googlebot/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            return new Bot(Brand.GOOGLE, BotFamily.CRAWLER, "Google Bot", ver, getAndConsumeUrl(context, MatchingRegion.PARENTHESIS, "+http://"));

            // Microsoft Bots
        } else if ((ver=context.getcVersionAfterPattern("msnbot/", MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            return new Bot(Brand.MICROSOFT, BotFamily.CRAWLER, "MSN Bot", ver, getAndConsumeUrl(context, MatchingRegion.PARENTHESIS, "http://"));
        } else if ((ver=context.getcVersionAfterPattern("msnbot-NewsBlogs/", MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            return new Bot(Brand.MICROSOFT, BotFamily.CRAWLER, "MSN Bot (news blogs)", ver, getAndConsumeUrl(context, MatchingRegion.PARENTHESIS, "http://"));
        } else if ((ver=context.getcVersionAfterPattern("msnbot-Products/", MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            return new Bot(Brand.MICROSOFT, BotFamily.CRAWLER, "MSN Bot (products)", ver, getAndConsumeUrl(context, MatchingRegion.PARENTHESIS, "http://"));
        } else if ((ver=context.getcVersionAfterPattern("msnbot-media/", MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            return new Bot(Brand.MICROSOFT, BotFamily.CRAWLER, "MSN Bot (media)", ver, getAndConsumeUrl(context, MatchingRegion.PARENTHESIS, "http://"));
        } else if ((ver=context.getcVersionAfterPattern("bingbot/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            return new Bot(Brand.MICROSOFT, BotFamily.CRAWLER, "Bing Bot", ver, consumeUrlAndMozilla(context,"http://www.bing"));

            // Baidu Bots

        } else if (context.contains("Baiduspider", MatchingType.BEGINS, MatchingRegion.BOTH)) {
            Bot res = null;

            if (context.consume("Baiduspider-image", MatchingType.BEGINS, MatchingRegion.BOTH)) {
                res = new Bot(Brand.BAIDU,BotFamily.CRAWLER,"Baidu Image search", "");
            } else if (context.consume("Baiduspider-video", MatchingType.BEGINS, MatchingRegion.BOTH)) {
                res = new Bot(Brand.BAIDU,BotFamily.CRAWLER,"Baidu Video search", "");
            } else if (context.consume("Baiduspider-news", MatchingType.BEGINS, MatchingRegion.BOTH)) {
                res = new Bot(Brand.BAIDU,BotFamily.CRAWLER,"Baidu News search", "");
            } else if (context.consume("Baiduspider-favo", MatchingType.BEGINS, MatchingRegion.BOTH)) {
                res = new Bot(Brand.BAIDU,BotFamily.CRAWLER,"Baidu collection search", "");
            } else if (context.consume("Baiduspider-cpro", MatchingType.BEGINS, MatchingRegion.BOTH)) {
                res = new Bot(Brand.BAIDU,BotFamily.CRAWLER,"Baidu Union search", UserAgentDetectionHelper.getVersionNumber(context.getUA(),pos+16));
            } else if (context.consume("Baiduspider-ads", MatchingType.BEGINS, MatchingRegion.BOTH)) {
                res = new Bot(Brand.BAIDU,BotFamily.CRAWLER,"Baidu Business search", UserAgentDetectionHelper.getVersionNumber(context.getUA(),pos+16));
            } else if (context.consume("Baiduspider", MatchingType.BEGINS, MatchingRegion.BOTH)) {
                res = new Bot(Brand.BAIDU,BotFamily.CRAWLER,"Baidu Web search", "");
            }


            if (res !=null) {
                res.setUrl( consumeUrlAndMozilla(context,"http://"));
                return res;
            }
        } else

            // Yandex bots
            if (
                null != (ver=context.getcToken("Yandex/", MatchingType.BEGINS, MatchingRegion.REGULAR)) || // Yandex.Image indexer;
                null != (ver=context.getcToken("YandexVideo/", MatchingType.BEGINS, MatchingRegion.BOTH)) || // Yandex.Video indexer;
                null != (ver=context.getcToken("YandexBlogs/", MatchingType.BEGINS, MatchingRegion.BOTH)) || // blog search robot, indexing post comments;
                null != (ver=context.getcToken("YandexWebmaster/", MatchingType.BEGINS, MatchingRegion.BOTH)) || //  a robot that has been directed to a page through the
                null != (ver=context.getcToken("YandexPagechecker/", MatchingType.BEGINS, MatchingRegion.BOTH)) || // a robot that validates the micro markup of a page using the "?" form;
                null != (ver=context.getcToken("YandexDirect/", MatchingType.BEGINS, MatchingRegion.BOTH)) || // robot indexing pages of sites belonging to the Yandex Advertising Network;
                null != (ver=context.getcToken("YandexDirect/", MatchingType.BEGINS, MatchingRegion.BOTH)) || // Yandex.Direct robot. This checks the accuracy of an advertised link before moderation;
                null != (ver=context.getcToken("YandexMetrika/", MatchingType.BEGINS, MatchingRegion.BOTH)) || //  Yandex.Metrica robot;
                null != (ver=context.getcToken("YandexNews/", MatchingType.BEGINS, MatchingRegion.BOTH)) || // Yandex.News robot;
                null != (ver=context.getcToken("YandexCatalog/", MatchingType.BEGINS, MatchingRegion.BOTH)) || // Yandex.Catalog robot. If a site is offline for several days, it is removed from Catalog. As soon as the site comes online, it will automatically begin to appear in Catalog again.
                null != (ver=context.getcToken("YandexZakladki/", MatchingType.BEGINS, MatchingRegion.BOTH)) || // a robot used to verify the availability of pages added to Yandex.Bookmarks;
                null != (ver=context.getcToken("YandexMarket/", MatchingType.BEGINS, MatchingRegion.BOTH))) { // Yandex.Market robot.
                String[]vv = ver.split("/");
                context.consume("Win16", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
                context.consume("[HI]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
                context.consume("m", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                context.consume("P", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                context.consume("MirrorDetector", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
                return new Bot(Brand.BAIDU, BotFamily.CRAWLER, "Yandex Crawler", vv[1].trim(), consumeUrlAndMozilla(context,"http://"));

                // Sogou bots

            } else if ((multi = context.getcNextTokens(new Matcher[] {new Matcher("Sogou", MatchingType.EQUALS),
                new Matcher("web", MatchingType.EQUALS),
                new Matcher("spider/", MatchingType.BEGINS)
            },
        MatchingRegion.REGULAR)) != null) {
            return new Bot(Brand.SOGOU, BotFamily.CRAWLER, "Web spider", multi[2].substring(7), getAndConsumeUrl(context, MatchingRegion.PARENTHESIS, "http://"));
        }
        else if ((multi = context.getcNextTokens(new Matcher[] {new Matcher("Sogou", MatchingType.EQUALS),
                 new Matcher("Pic", MatchingType.EQUALS),
                 new Matcher("Spider/", MatchingType.BEGINS)
        },
        MatchingRegion.REGULAR)) != null) {
            return new Bot(Brand.SOGOU, BotFamily.CRAWLER, "Image spider", multi[2].substring(7), getAndConsumeUrl(context, MatchingRegion.PARENTHESIS, "http://"));
        }


        // MISC BOTS

        else if ((ver = context.getcVersionAfterPattern("Applebot/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) != null) {
            return new Bot(Brand.APPLE, BotFamily.CRAWLER, "Applebot", ver, getAndConsumeUrl(context, MatchingRegion.PARENTHESIS, "http://"));

        } else if ((ver = context.getcVersionAfterPattern("Feedly/", MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
            context.consume("like ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            return new Bot(Brand.OTHER, BotFamily.FEED_CRAWLER, "Feedly", ver, getAndConsumeUrl(context, MatchingRegion.PARENTHESIS, "http://"));

        } else if (context.consume("TencentTraveler", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            return new Bot(Brand.TENCENT, BotFamily.CRAWLER, "Tencent Traveler", ver);

        } else if (context.consume("Ask Jeeves", MatchingType.BEGINS, MatchingRegion.BOTH) ||
                   context.consume("Teoma/", MatchingType.BEGINS, MatchingRegion.BOTH)) {
            context.consume("@", MatchingType.CONTAINS, MatchingRegion.PARENTHESIS);
            context.consume("Question and Answer Search", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume("Mozilla/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            context.consume("Jeeves", MatchingType.EQUALS, MatchingRegion.BOTH);
            ver = context.getcVersionAfterPattern("Teoma/Nutch-", MatchingType.BEGINS, MatchingRegion.REGULAR);
            if (ver != null) {
                ver = "Nutch " + ver;
            } else ver = "";

            return new Bot(Brand.ASK, BotFamily.CRAWLER, "Ask Jeeves web search bot (former Teoma)", ver, consumeUrlAndMozilla(context,"http://"));

        } else if (context.consume("ia_archiver", MatchingType.BEGINS, MatchingRegion.BOTH)) {
            context.consume("@", MatchingType.CONTAINS, MatchingRegion.PARENTHESIS);
            context.consume("+http://", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            return new Bot(Brand.AMAZON, BotFamily.CRAWLER, "Amazon's Alexa web crawler", "");

        } else if ((multi = context.getcNextTokens(new Matcher[] {new Matcher("VoilaBot", MatchingType.EQUALS),
            new Matcher("BETA", MatchingType.EQUALS),
            new Matcher("^[0-9\\.]+$", MatchingType.REGEXP)
        },
        MatchingRegion.REGULAR)) != null) {
            context.consume("@", MatchingType.CONTAINS, MatchingRegion.PARENTHESIS);
            context.consume("rv:", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            return new Bot(Brand.ORANGE, BotFamily.CRAWLER, "Voila Bot (Beta)", multi[2], consumeUrlAndMozilla(context,"http://"));

        }
        else if ((ver=context.getcVersionAfterPattern("Twiceler-", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) != null) {
            String browser = "Twiceler " + ver;
            return new Bot(Brand.CUIL, BotFamily.CRAWLER, "Twiceler", ver, consumeUrlAndMozilla(context,"http://"));
        } else if ((ver=context.getcVersionAfterPattern("emefgebot/", MatchingType.BEGINS, MatchingRegion.BOTH)) != null) {
            return new Bot(Brand.OTHER, BotFamily.CRAWLER, "emefge bot", "", consumeUrlAndMozilla(context,"http://"));
        } else if ((ver=context.getcVersionAfterPattern("YodaoBot/", MatchingType.BEGINS, MatchingRegion.BOTH)) != null ||
                   (ver=context.getcVersionAfterPattern("+YodaoBot/", MatchingType.BEGINS, MatchingRegion.BOTH)) != null) {
            String url = consumeUrlAndMozilla(context,"http://");
            if (url == null) url = consumeUrlAndMozilla(context,"+http://");
            context.consume("+", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            return new Bot(Brand.NETEASE, BotFamily.CRAWLER, "Yodao Bot", ver, url);
        } else if ((ver=context.getcVersionAfterPattern("YodaoBot-Image/", MatchingType.BEGINS, MatchingRegion.BOTH)) != null) {
            return new Bot(Brand.NETEASE, BotFamily.CRAWLER, "Yodao Image Bot", ver, consumeUrlAndMozilla(context,"http://"));
        } else if ((ver=context.getcVersionAfterPattern("YodaoBot-Mobile/", MatchingType.BEGINS, MatchingRegion.BOTH)) != null) {
            return new Bot(Brand.NETEASE, BotFamily.CRAWLER, "Yodao Mobile Bot", ver);
        } else if (context.getcNextTokens(new Matcher[] {new Matcher("Speedy",MatchingType.EQUALS),
            new Matcher("Spider",MatchingType.EQUALS),
        }, MatchingRegion.REGULAR) != null) {
            context.consume("Entireweb", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            ver = context.getcVersionAfterPattern("Beta/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            return new Bot(Brand.ENTIREWEB, BotFamily.CRAWLER, "Speedy Spider", ver == null ? "" : (ver + " beta"), consumeUrlAndMozilla(context,"http://"));
        }
        else if (context.getcNextTokens(new Matcher[] {new Matcher("Typhoeus",MatchingType.EQUALS),
                 new Matcher("-",MatchingType.EQUALS),
                 new Matcher("https://github.com/typhoeus/typhoeus",MatchingType.EQUALS),
        }, MatchingRegion.REGULAR) != null) {
            return new Bot(Brand.OPENSOURCE_COMMUNITY, BotFamily.ROBOT, "Typhoeus library", "");
        }
        else if ((ver=context.getcVersionAfterPattern("FSPBot/",MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            return new Bot(Brand.OTHER, BotFamily.SPAMBOT, "FSPBot", ver);
        } else if ((ver=context.getcVersionAfterPattern("SiteSucker/",MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            return new Bot(Brand.OTHER, BotFamily.ROBOT, "SiteSucker", ver);
        } else if (context.consume("360Spider",MatchingType.EQUALS, MatchingRegion.REGULAR)) {
            if (context.consume("HaosouSpider",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                context.consume(";",MatchingType.EQUALS, MatchingRegion.REGULAR);
                context.consume("compatible", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                return new Bot(Brand.HAOSOU, BotFamily.CRAWLER, "Haosou Crawler", "", getAndConsumeUrl(context,MatchingRegion.PARENTHESIS, "http://"));
            }
            return new Bot(Brand.OTHER, BotFamily.ROBOT, "360 Spider", "");
        } else if ((ver=context.getcVersionAfterPattern("FlipboardProxy/",MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            return new Bot(Brand.OTHER, BotFamily.ROBOT, "Flipboard Proxy", ver, consumeUrlAndMozilla(context,"http://"));
        } else if (context.consume("Exabot/",MatchingType.BEGINS, MatchingRegion.BOTH) || context.consume("Exabot-Test/",MatchingType.BEGINS, MatchingRegion.BOTH)) {
            context.consume("BiggerBetter", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            return new Bot(Brand.EXALEAD, BotFamily.CRAWLER, "Exalead crawler", "", consumeUrlAndMozilla(context,"http://"));
        } else if (context.consume("MRSPUTNIK (OW )?([0-9], )+[0-9]+( [SH]W)?",MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) {
            return new Bot(Brand.OTHER, BotFamily.SPAMBOT, "MRS PUTNIK", "");
        } else if (context.consume("ips-agent",MatchingType.EQUALS, MatchingRegion.BOTH)) {
            return new Bot(Brand.OTHER, BotFamily.ROBOT, "VeriSign Bot", "");
        } else if (context.consume("ichiro/mobile goo",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            return new Bot(Brand.OTHER, BotFamily.CRAWLER, "Goo crawler", "");
        }


        /*else if ((pos=userAgent.indexOf("webcrawler/"))>-1) {
            String browser = "WebCrawler " + getVersionNumber(userAgent,pos+11);
          } else // The following two bots don't have any version number in their User-Agent strings.
            if ((pos=userAgent.indexOf("inktomi"))>-1) {
            String browser = "Inktomi";
          } else if ((pos=userAgent.indexOf("teoma"))>-1) {
            String browser = "Teoma";
          }*/


        return new Bot(Brand.UNKNOWN, BotFamily.NOT_A_BOT, "", "", "");
    }

    static void setMacOSFromCFNetwork(UserAgentDetectionResult results, String cfver, String dver) {
        String key = cfver + "/" + dver;
        OS os = mapCfNetworkOS.get(key);
        String arch = mapCfNetworkArchitecture.get(key);
        if (os != null) results.setOperatingSystem(os);
        else results.setOperatingSystem(new OS(Brand.APPLE, OSFamily.UNKNOWN, "iOS or MacOS", ""));
        if (arch != null) results.getDevice().setArchitecture(arch);
    }


    static String getDeviceFromCFNetwork(UserAgentContext context, String pattern) {
        String dev;
        if ((dev=context.getcToken(pattern+"[0-9(%2C),]+",MatchingType.REGEXP, MatchingRegion.PARENTHESIS))!=null) {
            return pattern + " " + dev.substring(pattern.length()).replace("%2C",",");
        }
        return null;
    }
    static void setDeviceFromCFNetwork(UserAgentContext context, UserAgentDetectionResult res) {
        String dev = getDeviceFromCFNetwork(context, "iMac");
        if (dev==null) dev = getDeviceFromCFNetwork(context, "MacBookAir");
        if (dev==null) dev = getDeviceFromCFNetwork(context, "MacBookPro");
        if (dev==null) dev = getDeviceFromCFNetwork(context, "MacPro");
        if (dev==null) dev = getDeviceFromCFNetwork(context, "MacBook");
        if (dev != null) res.getDevice().setDevice(dev);

    }

    public static UserAgentDetectionResult getLibraries(UserAgentContext context) {
        String ua = context.getUA();
        int pos=0;
        String ver,token;
        String[]groups;

        UserAgentDetectionResult res = new UserAgentDetectionResult(
            new Device("",DeviceType.COMPUTER,Brand.UNKNOWN,""),
            new Browser(Brand.UNKNOWN,BrowserFamily.LIBRARY,"",RenderingEngine.getUnknown()),
            new OS(Brand.UNKNOWN,OSFamily.LINUX,"Linux",""));


        if ((groups = getGroups("Curl/PHP ([0-9\\.]+)(-[0-9]ubuntu[0-9\\.]+)? \\(http://github.com/shuber/curl\\)", context.getUA(), 1, 2)) != null) {
            res.getBrowser().setFullVersionOneShot(groups[0], 2);
            res.getBrowser().setDescription("curl");
            res.getBrowser().setFamily(BrowserFamily.LIBRARY);
            res.getBrowser().setVendor(Brand.OPENSOURCE_COMMUNITY);

            if (!StringUtils.isNullOrEmpty(groups[1])) {
                res.getOperatingSystem().setFamily(OSFamily.LINUX);
                res.getOperatingSystem().setDescription("Ubuntu");
            }

            context.consumeAllTokens();
            return res;
        } else if ((ver=context.getcVersionAfterPattern("libcurl/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
            String archTotal = context.getcToken("",MatchingType.ALWAYS_MATCH, MatchingRegion.PARENTHESIS);
            if (archTotal == null) archTotal = "";
            String arch;
            if ((pos=archTotal.indexOf("-"))>-1) {
                arch = archTotal.substring(0,pos);
            } else {
                arch = "";
            }
            res.getDevice().setArchitecture(arch);
            res.getBrowser().setFullVersionOneShot(ver, 2);
            res.getBrowser().setDescription("curl");
            res.getBrowser().setFamily(BrowserFamily.LIBRARY);
            res.getBrowser().setVendor(Brand.OPENSOURCE_COMMUNITY);

            context.consume("curl/",MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("NSS/",MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("zlib/",MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("libidn/",MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("libssh2/",MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("OpenSSL/",MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("librtmp/",MatchingType.BEGINS, MatchingRegion.REGULAR);

            if (archTotal.indexOf("-pc-")>-1) {
                res.getDevice().setDevice("PC");
            }

            if (archTotal.endsWith("-redhat-linux-gnu")) {
                res.getOperatingSystem().setVersion(("Red Hat " + arch).trim());
                return res;
            } else if (archTotal.endsWith("-pc-win32")) {
                res.getDevice().setBrandAndManufacturer(Brand.UNKNOWN);
                res.getOperatingSystem().setFamily(OSFamily.WINDOWS);
                res.getOperatingSystem().setDescription("Windows");
                res.getOperatingSystem().setVersion(arch);
                return res;
            } else if (archTotal.endsWith("pc-mingw32msvc")) {
                res.getDevice().setBrandAndManufacturer(Brand.UNKNOWN);
                res.getOperatingSystem().setFamily(OSFamily.WINDOWS);
                res.getOperatingSystem().setDescription("Windows");
                res.getOperatingSystem().setVersion((arch + " through MinGW").trim());
                return res;
            } else if ((pos=archTotal.indexOf("-apple-darwin"))>-1) {
                res.getDevice().setBrandAndManufacturer(Brand.APPLE);
                res.getDevice().setDevice("Macintosh");
                res.getOperatingSystem().setFamily(OSFamily.MACOSX);
                res.getOperatingSystem().setDescription("Mac OS");
                res.getOperatingSystem().setVersion( "darwin "+UserAgentDetectionHelper.getVersionNumber(archTotal,pos+13)+ (arch.equals("universal")?(""):(" " + arch)));
                return res;
            } else if (archTotal.endsWith("-linux-gnu")) {
                res.getOperatingSystem().setVersion(arch);
                return res;
            } else if ((pos=archTotal.indexOf("-portbld-freebsd"))>-1) {
                res.getOperatingSystem().setFamily(OSFamily.BSD);
                res.getOperatingSystem().setDescription("FreeBSD");
                res.getOperatingSystem().setVersion( (UserAgentDetectionHelper.getVersionNumber(archTotal,pos+16) + " "+arch).trim());
                return res;
            }
        } else if ((ver=context.getcVersionAfterPattern("curl/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
            res.getBrowser().setFullVersionOneShot(ver, 2);
            res.getBrowser().setDescription("curl");
            res.getBrowser().setFamily(BrowserFamily.LIBRARY);
            res.getBrowser().setVendor(Brand.OPENSOURCE_COMMUNITY);
            return res;
        } else if ((ver=context.getcVersionAfterPattern("CFNetwork/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
            // A library on MacOS and iOS to make network calls.
            res.getBrowser().setFamily(BrowserFamily.LIBRARY);
            res.getBrowser().setDescription("CFNetwork");
            res.getBrowser().setVendor(Brand.APPLE);
            String cfnver = ver;
            res.getBrowser().setFullVersionOneShot(cfnver, 2);
            String dver = context.getcVersionAfterPattern("Darwin/",MatchingType.BEGINS, MatchingRegion.REGULAR);
            if (dver == null) dver = "";
            if ((ver=context.getcVersionAfterPattern("Flipboard/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.FLIPBOARD, BotFamily.ROBOT, "Flipboard", ver));
            } else if ((ver=context.getcVersionAfterPattern("Puffin/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.CLOUDMOSA, BotFamily.ROBOT, "Puffin Browser", ver));
            } else if ((ver=context.getcVersionAfterPattern("Mercury/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.ILEGEND, BotFamily.ROBOT, "Mercury Browser", ver));
            } else if ((ver=context.getcVersionAfterPattern("Instapaper/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.INSTAPAPER, BotFamily.ROBOT, "Instapaper", ver));
            } else if ((ver=context.getcVersionAfterPattern("InstapaperPro/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.INSTAPAPER, BotFamily.ROBOT, "InstapaperPro", ver));
            } else if ((ver=context.getcVersionAfterPattern("Readability/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.READABILITY, BotFamily.ROBOT, "Readability", ver));
            } else if ((ver=context.getcVersionAfterPattern("QQ/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.TENCENT, BotFamily.ROBOT, "QQ Messaging App", ver));
            } else if ((ver=context.getcVersionAfterPattern("Reeder/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.REEDER, BotFamily.ROBOT, "Reeder", ver));
            } else if ((ver=context.getcVersionAfterPattern("EvernoteShare/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.MOBOTAP, BotFamily.ROBOT, "Evernote Share for Dolphin Browser", ver));
            } else if ((ver=context.getcVersionAfterPattern("ReadKit/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.WEBIN, BotFamily.ROBOT, "ReadKit", ver));
            } else if ((ver=context.getcVersionAfterPattern("Spillo/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.BANANAFISH, BotFamily.ROBOT, "Spillo", ver));
            } else if ((ver=context.getcVersionAfterPattern("Pinner/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.UNKNOWN, BotFamily.ROBOT, "Pinner", ver));
            } else if ((ver=context.getcVersionAfterPattern("LinkedIn/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.LINKEDIN, BotFamily.ROBOT, "LinkedIn", ver));
            } else if ((ver=context.getcVersionAfterPattern("CloudyTabs/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.UNKNOWN, BotFamily.ROBOT, "Cloudy Tabs", ver));
            } else if ((ver=context.getcVersionAfterPattern("Opera%20Coast/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.OPERA, BotFamily.ROBOT, "Opera Coast", ver));
            } else if ((ver=context.getcVersionAfterPattern("iCabMobile/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.UNKNOWN, BotFamily.ROBOT, "iCab Mobile", ver));
            } else if ((ver=context.getcVersionAfterPattern("CLIPish%20Jr/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.UNKNOWN, BotFamily.ROBOT, "CLIPish", ver));
            } else if ((ver=context.getcVersionAfterPattern("Bing/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.MICROSOFT, BotFamily.ROBOT, "Bing App", ver));
            } else if ((ver=context.getcVersionAfterPattern("InDesign/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.ADOBE, BotFamily.ROBOT, "InDesign App", ver));
            } else if ((ver=context.getcVersionAfterPattern("AlienBlue/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null ||
                       (ver=context.getcVersionAfterPattern("AlienBlueHD/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.REDDIT, BotFamily.ROBOT, "Reddit App", ver));
            } else if ((ver=context.getcVersionAfterPattern("Newsify/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.UNKNOWN, BotFamily.ROBOT, "Newsify App", ver));
            } else if ((ver=context.getcVersionAfterPattern("Ziner/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.UNKNOWN, BotFamily.ROBOT, "Ziner App", ver));
            } else if ((ver=context.getcVersionAfterPattern("Leaf/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.ROCKYSAND, BotFamily.ROBOT, "Leaf RSS reader App", ver));
            } else if ((ver=context.getcVersionAfterPattern("Newsflow/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.ROCKYSAND, BotFamily.ROBOT, "Newsflow RSS reader App", ver));
            } else if ((ver=context.getcVersionAfterPattern("RSS%20Notifier/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.ROCKYSAND, BotFamily.ROBOT, "RSS Notifier App", ver));
            } else if ((ver=context.getcVersionAfterPattern("Redd/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.UNKNOWN, BotFamily.ROBOT, "Redd reddit client App", ver));
            } else if ((ver=context.getcVersionAfterPattern("Hacker%20News/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.UNKNOWN, BotFamily.ROBOT, "Hacker News App", ver));
            } else if ((ver=context.getcVersionAfterPattern("Buffer/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.UNKNOWN, BotFamily.ROBOT, "Buffer App", ver));
            } else if ((ver=context.getcVersionAfterPattern("Buffer/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.UNKNOWN, BotFamily.ROBOT, "Buffer App", ver));
            } else if ((ver=context.getcVersionAfterPattern("AtomicLite/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null ||
                       (ver=context.getcVersionAfterPattern("AtomicBrowser/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.UNKNOWN, BotFamily.ROBOT, "Atomic Web Browser", ver));
            } else if ((ver=context.getcVersionAfterPattern("Tweetbot/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null ||
                       (ver=context.getcVersionAfterPattern("TweetbotPad/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.UNKNOWN, BotFamily.ROBOT, "Tweetbot App", ver));
            } else if ((ver=context.getcVersionAfterPattern("onesafe%20iOS/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.LUNABEE, BotFamily.ROBOT, "OneSafe App", ver));
            } else if ((ver=context.getcVersionAfterPattern("Stache/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.UNKNOWN, BotFamily.ROBOT, "Stache Bookmarking App", ver));
            } else if ((ver=context.getcVersionAfterPattern("Pins/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.UNKNOWN, BotFamily.ROBOT, "Pins App", ver));
            } else if ((ver=context.getcVersionAfterPattern("Pinterest/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                res.setBot(new Bot(Brand.PINTEREST, BotFamily.ROBOT, "Pinterest", ver));
            } else if (context.consume("MobileSafari/",MatchingType.BEGINS, MatchingRegion.REGULAR) ||
                       context.consume("Safari/",MatchingType.BEGINS, MatchingRegion.REGULAR) ||
                       context.consume("Safari[0-9\\.]+",MatchingType.REGEXP, MatchingRegion.REGULAR) ||
                       context.consume("com.apple.WebKit.Networking/",MatchingType.BEGINS, MatchingRegion.REGULAR) ||
                       context.consume("com.apple.WebKit.WebContent/",MatchingType.BEGINS, MatchingRegion.REGULAR)) {
            } else {
                int fsp = context.getUA().indexOf(" ");
                int fsl = context.getUA().indexOf("/");
                if (fsp>-1 && fsl>-1 && fsl<fsp) {
                    String botName = context.getUA().substring(0, fsl);
                    ver=context.getcVersionAfterPattern(botName+"/",MatchingType.BEGINS, MatchingRegion.REGULAR);
                    res.setBot(new Bot(Brand.UNKNOWN, BotFamily.ROBOT, "Unknown bot " + botName, ver==null ? "" : ver));
                } else {
                    res.setBot(new Bot(Brand.UNKNOWN, BotFamily.ROBOT, "Unknown bot", ""));
                }
            }
            setMacOSFromCFNetwork(res, cfnver, dver);
            setDeviceFromCFNetwork(context, res);
            if (context.consume("x86_64", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) res.getDevice().setArchitecture("x86_64");
            if (context.consume("i386", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) res.getDevice().setArchitecture("i386");
            UserAgentDetectionHelper.addExtensionsCommonForLibs(context, res);
            return res;
        } else if ((ver=context.getcVersionAfterPattern("HTTP_Request2/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
            res.getBrowser().setFamily(BrowserFamily.LIBRARY);
            res.getBrowser().setVendor(Brand.OPENSOURCE_COMMUNITY);
            res.getBrowser().setDescription("PHP HttpRequest2");
            res.getBrowser().setFullVersionOneShot(ver, 2);

            context.consume("http://",MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            String phpVer = context.getcVersionAfterPattern("PHP/",MatchingType.BEGINS, MatchingRegion.REGULAR);

            if (phpVer.indexOf("-")>-1 && phpVer.indexOf("ubuntu")>-1) {
                res.getOperatingSystem().setDescription("Ubuntu");
                phpVer = phpVer.substring(0, phpVer.indexOf("-"));
            } else {
                res.setOperatingSystem(new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"",""));
            }

            if (phpVer!=null) res.getBrowser().fullVersion += " php " + phpVer;

            return res;
        } else if ((context.getUA().length() == 4 && context.consume("Ruby",MatchingType.EQUALS, MatchingRegion.REGULAR)) ||
                   (ver=context.getcVersionAfterPattern("Ruby/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null ||
                   (ver=context.getcToken("[0-9\\.]+, ruby [0-9\\.]+",MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) != null) {
            if (ver != null && ver.indexOf(" ruby ")>0)
                ver = ver.substring(ver.indexOf(" ruby ")+6);
            String rver = ver;

            res.getBrowser().setFamily(BrowserFamily.LIBRARY);
            res.getBrowser().setVendor(Brand.OPENSOURCE_COMMUNITY);
            res.getBrowser().setDescription("Ruby");
            res.setOperatingSystem(new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"",""));

            if ((ver=context.getcVersionAfterPattern("Mechanize/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                context.consume("http://",MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
                res.getBrowser().setDescription("Mechanize (Ruby)");
            } else if ((ver=context.getcVersionAfterPattern("HTTPClient/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                context.consume("[0-9]{4}-[0-9]{2}-[0-9]{2}",MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
                res.getBrowser().setDescription("HTTPClient (Ruby"+(rver!=null?" "+rver:"")+")");
            } else if (context.consume("Atig::Http/",MatchingType.BEGINS, MatchingRegion.REGULAR)) {
                if (context.consume("arm-linux.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) {
                    res.getDevice().setArchitecture("arm");
                    res.getOperatingSystem().setFamily(OSFamily.LINUX);
                    res.getOperatingSystem().setDescription("Linux");
                } else if (context.consume("i386-linux.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) {
                    res.getDevice().setArchitecture("i386");
                    res.getOperatingSystem().setFamily(OSFamily.LINUX);
                    res.getOperatingSystem().setDescription("Linux");
                } else if (context.consume("i686-linux.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) {
                    res.getDevice().setArchitecture("i686");
                    res.getOperatingSystem().setFamily(OSFamily.LINUX);
                    res.getOperatingSystem().setDescription("Linux");
                } else if (context.consume("x86_64-linux.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) {
                    res.getDevice().setArchitecture("x86_64");
                    res.getOperatingSystem().setFamily(OSFamily.LINUX);
                    res.getOperatingSystem().setDescription("Linux");
                }
                res.getBrowser().setDescription("Atig (Ruby)");

                context.consume("http.rb", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                context.consume("net-irc", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            }
            if (ver != null) res.getBrowser().setFullVersionOneShot(ver, 2);
            else if (rver != null) res.getBrowser().setFullVersionOneShot(rver, 2);

            return res;
        } else if ((ver=context.getcVersionAfterPattern("Commons-HttpClient/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null ||
                   (ver=context.getcVersionAfterPattern("Apache-HttpClient/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
            context.consume("Jakarta",MatchingType.EQUALS, MatchingRegion.REGULAR);
            context.consume("java ",MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            res.getBrowser().setFamily(BrowserFamily.LIBRARY);
            res.getBrowser().setVendor(Brand.APACHE);
            res.getBrowser().setDescription("Commons HttpClient");
            res.getBrowser().setFullVersionOneShot(ver, 2);
            res.setOperatingSystem(new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"",""));
            return res;
        } else if ((ver=context.getcVersionAfterPattern("Wget/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
            res.getBrowser().setFamily(BrowserFamily.LIBRARY);
            res.getBrowser().setVendor(Brand.OPENSOURCE_COMMUNITY);
            res.getBrowser().setDescription("wget");
            res.getBrowser().setFullVersionOneShot(ver, 2);

            if (context.consume("Red Hat modified",MatchingType.EQUALS, MatchingRegion.PARENTHESIS) ||
            context.getcNextTokens(new Matcher[] {new Matcher("Red",MatchingType.EQUALS),
                                       new Matcher("Hat",MatchingType.EQUALS),
                                       new Matcher("modified",MatchingType.EQUALS)
            }, MatchingRegion.REGULAR)!=null) {
                res.getOperatingSystem().setVersion("Red Hat");
                return res;
            }
            else if (context.consume("linux-gnu",MatchingType.EQUALS, MatchingRegion.BOTH)) {
                return res;
            } else if ((ver=context.getcVersionAfterPattern("freebsd",MatchingType.BEGINS, MatchingRegion.BOTH))!=null) {
                res.getOperatingSystem().setFamily(OSFamily.BSD);
                res.getOperatingSystem().setDescription("FreeBSD");
                res.getOperatingSystem().setVersion(ver);
                return res;
            } else if (context.consume("cygwin",MatchingType.EQUALS, MatchingRegion.BOTH)) {
                res.getDevice().setBrandAndManufacturer(Brand.UNKNOWN);
                res.getOperatingSystem().setFamily(OSFamily.WINDOWS);
                res.getOperatingSystem().setDescription("Windows");
                res.getOperatingSystem().setVersion("through cygwin");
                return res;
            } else {
                res.setOperatingSystem(new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"",""));
                return res;
            }
        } else if (context.getcNextTokens(new Matcher[] {new Matcher("Xenu",MatchingType.EQUALS),
            new Matcher("Link",MatchingType.EQUALS),
            new Matcher("Sleuth",MatchingType.BEGINS)
        }, MatchingRegion.REGULAR) != null) {
            token = context.getcVersionAfterPattern("Sleuth/",MatchingType.BEGINS, MatchingRegion.CONSUMED);
            if (token == null) {
                token = context.getcToken("",MatchingType.ALWAYS_MATCH, MatchingRegion.REGULAR);
            }
            context.consume("beta",MatchingType.BEGINS, MatchingRegion.BOTH);
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.COMPUTER,Brand.UNKNOWN,""),
                       new Browser(Brand.UNKNOWN,BrowserFamily.UNKNOWN,"",RenderingEngine.getUnknown()),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"",""),
                       new Bot(Brand.OTHER, BotFamily.ROBOT, "Xenu Link Sleuth", token));

        }
        return null;
    }

    public static void addLibrary(UserAgentContext context, UserAgentDetectionResult res) {
        String ver;
        if (!context.contains("Java/Jbed",  MatchingType.BEGINS, MatchingRegion.REGULAR)) {
            String jv = null;
            if ((ver = context.getcVersionAfterPattern("Java/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
                context.consume("Mozilla/",MatchingType.BEGINS,MatchingRegion.REGULAR);
                jv = ver;
            } else if ((ver = context.getcVersionAfterPattern("java ",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                jv = ver;
            }
            if (jv != null) {
                res.getBrowser().setFamily(BrowserFamily.LIBRARY);
                res.getBrowser().setVendor(Brand.SUN);
                res.getBrowser().setDescription("Java");
                res.getBrowser().setFullVersionOneShot(jv, 2);
            }
        }
    }


}