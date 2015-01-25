package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
/**
* This is the documentation for the version _DEV_VERSION_ of the library.
*/
public class UserAgentDetector implements IUserAgentDetector {
    public static final String VERSION = "_DEV_VERSION_";

    String keepPos(String version, int position) {
        int pd = 0;
        for (int i=0 ; i<version.length() ; i++) {
            if (!Character.isDigit(version.charAt(i))) {
                pd++;
                if (pd>=position) return version.substring(0,i);
            }
        }
        return version;
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

    static void consumeMozilla(UserAgentContext context) {
        context.consume("compatible", MatchingType.CONTAINS, MatchingRegion.PARENTHESIS);
        context.consume("Mozilla/", MatchingType.BEGINS, MatchingRegion.REGULAR);
    }

    static void consumeUrlAndMozilla(UserAgentContext context, String url) {
        context.consume(url, MatchingType.CONTAINS, MatchingRegion.PARENTHESIS);
        consumeMozilla(context);
    }

    static void consumeRegularWindowsGarbage(UserAgentContext context) {
        context.consume("Windows", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.consume("Windows", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
        context.consume("U", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.consume("rv:[0-9]\\.[0-9]\\.[0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
    }

    static void consumeWebKitBullshit(UserAgentContext context) {
        consumeMozilla(context);
        if (!context.consume("AppleWebKit/", MatchingType.BEGINS, MatchingRegion.REGULAR))
            context.consume("AppleWebkit/", MatchingType.BEGINS, MatchingRegion.REGULAR);
        context.consume("Safari/", MatchingType.BEGINS, MatchingRegion.REGULAR);
        context.consume("Mobile", MatchingType.EQUALS, MatchingRegion.REGULAR);
        context.consume("KHTML, [lL]ike Gecko", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
    }

    static UserAgentDetectionResult getBot(UserAgentContext context) {
        int pos=0;
        String ver;
        String[]multi;

        if (context.getUA().startsWith("WordPress/")) {
            String browser = "";
            context.ignoreAllTokens();
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.UNKNOWN,""),
                       new Browser(Brand.UNKNOWN,BrowserFamily.ROBOT,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,browser, browser));
        }
        if (context.getUA().indexOf("<a href=\"")>-1 && context.getUA().endsWith("</a> (Windows NT 5.1; U; en) Presto/2.10.229 Version/11.60")) {
            String browser = "Known Spam Bot";
            context.consumeAllTokens();
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.SPAMBOT,Brand.UNKNOWN,"Link reference bombing"),
                       new Browser(Brand.UNKNOWN,BrowserFamily.SPAMBOT,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,browser, browser));
        } else if (context.getLCUA().matches(".*<script>((window|document|top)\\.)?location(\\.href)?=.*")) {
            String browser = "Spam Bot";
            context.consumeAllTokens();
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.SPAMBOT,Brand.UNKNOWN,"Infected site honeypot"),
                       new Browser(Brand.UNKNOWN,BrowserFamily.SPAMBOT,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,browser, browser));

        } else if ((ver=context.getcVersionAfterPattern("Gnomit/",MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            String browser = "Gnomit crawler " + ver;

            consumeUrlAndMozilla(context,"http://");
            context.consume("X11", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume("Linux", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            String arch = context.getcToken("x86", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);

            return new UserAgentDetectionResult(
                       new Device((arch==null)?"":arch,DeviceType.BOT,Brand.UNKNOWN,"Gnomit crawler"),
                       new Browser(Brand.UNKNOWN,BrowserFamily.CRAWLER,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"),
                       getLocale(context));

        } else if (context.getLCUA().indexOf("<a href=\"")>-1 || context.getLCUA().indexOf("<a href=\'")>-1) {
            String browser = "Spam Bot";
            context.consumeAllTokens();
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.SPAMBOT,Brand.UNKNOWN,"Link reference bombing"),
                       new Browser(Brand.UNKNOWN,BrowserFamily.SPAMBOT,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,browser, browser));

            // GOOGLE BOTS

        } else if ((pos=context.getUA().indexOf("Googlebot-News"))>-1) {
            String browser = "Google News Bot " + getVersionNumber(context.getUA(),pos+15);
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.GOOGLE,"Google News bot"),
                       new Browser(Brand.GOOGLE,BrowserFamily.CRAWLER,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        } else if ((ver=context.getcVersionAfterPattern("Googlebot-Image/",MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            String browser = "Google Image Bot " + ver;
            context.consume("http://", MatchingType.CONTAINS, MatchingRegion.PARENTHESIS);
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.GOOGLE,"Google Image search bot"),
                       new Browser(Brand.GOOGLE,BrowserFamily.CRAWLER,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        } else if ((ver=context.getcVersionAfterPattern("Googlebot-Video/",MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            String browser = "Google Video Bot " + ver;
            context.consume("http://", MatchingType.CONTAINS, MatchingRegion.PARENTHESIS);
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.GOOGLE,"Google Video search bot"),
                       new Browser(Brand.GOOGLE,BrowserFamily.CRAWLER,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        } else if ((ver=context.getcVersionAfterPattern("Googlebot-Mobile/",MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            String browser = "Google Mobile Bot " + ver;
            context.ignoreAllTokens();
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.GOOGLE,"Google mobile search bot"),
                       new Browser(Brand.GOOGLE,BrowserFamily.CRAWLER,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        } else if ((ver=context.getcVersionAfterPattern("Mediapartners-Googlebot",MatchingType.BEGINS, MatchingRegion.BOTH))!=null) {
            String browser = "Google Adsense Bot " + ver;
            context.ignoreAllTokens();
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.GOOGLE,"Google Adsense search bot"),
                       new Browser(Brand.GOOGLE,BrowserFamily.CRAWLER,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        } else if ((ver=context.getcVersionAfterPattern("Mediapartners-Google",MatchingType.BEGINS, MatchingRegion.BOTH))!=null) {
            String browser = "Google Adsense Bot " + ver;
            context.ignoreAllTokens();
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.GOOGLE,"Google Adsense search bot"),
                       new Browser(Brand.GOOGLE,BrowserFamily.CRAWLER,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        } else if ((ver=context.getcVersionAfterPattern("AdsBot-Google-",MatchingType.BEGINS, MatchingRegion.REGULAR))!=null ||
                   context.consume("AdsBot-Google",MatchingType.BEGINS, MatchingRegion.REGULAR)) {
            String browser = ("Google AdsBot " + ((ver == null)?"":ver)).trim();
            context.ignoreAllTokens();
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.GOOGLE,"Google AdsBot web search bot"),
                       new Browser(Brand.GOOGLE,BrowserFamily.CRAWLER,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));

        } else if ((ver=context.getcVersionAfterPattern("Google Desktop",MatchingType.BEGINS, MatchingRegion.PARENTHESIS, 2))!=null) {
            String browser = ("Google Desktop " + ver).trim();

            consumeUrlAndMozilla(context, "http://");

            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.GOOGLE,"Google Desktop RSS reader"),
                       new Browser(Brand.GOOGLE,BrowserFamily.CRAWLER,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));

        } else if ((ver=context.getcVersionAfterPattern("Googlebot",MatchingType.BEGINS, MatchingRegion.PARENTHESIS, 2))!=null) {
            String browser = "Google Bot " + ver;
            consumeUrlAndMozilla(context,"http://");
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.GOOGLE,"Google web search bot"),
                       new Browser(Brand.GOOGLE,BrowserFamily.CRAWLER,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));

            // Microsoft Bots


        } else if ((ver=context.getcVersionAfterPattern("msnbot/", MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            String browser = "MSNBot " + ver;
            context.consume("http://search.msn.com/msnbot", MatchingType.CONTAINS, MatchingRegion.PARENTHESIS);
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.MICROSOFT,"MSN Bot"),
                       new Browser(Brand.MICROSOFT,BrowserFamily.CRAWLER,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        } else if ((ver=context.getcVersionAfterPattern("msnbot-NewsBlogs/", MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            String browser = "MSNBot NewsBlogs " + ver;
            context.consume("http://search.msn.com/msnbot", MatchingType.CONTAINS, MatchingRegion.PARENTHESIS);
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.MICROSOFT,"MSN NewsBlogs Bot"),
                       new Browser(Brand.MICROSOFT,BrowserFamily.CRAWLER,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        } else if ((ver=context.getcVersionAfterPattern("msnbot-Products/", MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            String browser = "MSNBot Products " + ver;
            context.consume("http://search.msn.com/msnbot", MatchingType.CONTAINS, MatchingRegion.PARENTHESIS);
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.MICROSOFT,"MSN Products Bot"),
                       new Browser(Brand.MICROSOFT,BrowserFamily.CRAWLER,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        } else if ((ver=context.getcVersionAfterPattern("msnbot-media/", MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            String browser = "MSNBot Media " + ver;
            context.consume("http://search.msn.com/msnbot", MatchingType.CONTAINS, MatchingRegion.PARENTHESIS);
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.MICROSOFT,"MSN Media Bot"),
                       new Browser(Brand.MICROSOFT,BrowserFamily.CRAWLER,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        } else if ((ver=context.getcVersionAfterPattern("bingbot/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            String browser = "Bing Bot " + ver;
            consumeUrlAndMozilla(context,"http://www.bing");
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.MICROSOFT,"Bing Bot"),
                       new Browser(Brand.MICROSOFT,BrowserFamily.CRAWLER,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));


            // Baidu Bots

        } else if (context.contains("Baiduspider", MatchingType.BEGINS, MatchingRegion.BOTH)) {
            UserAgentDetectionResult res = null;

            if (context.consume("Baiduspider-image", MatchingType.BEGINS, MatchingRegion.BOTH)) {
                String browser = "Baidu Image search";
                res = new UserAgentDetectionResult(new Device("",DeviceType.BOT,Brand.BAIDU,"Image search"),
                                                   new Browser(Brand.BAIDU,BrowserFamily.CRAWLER,browser, browser),
                                                   new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
            } else if (context.consume("Baiduspider-video", MatchingType.BEGINS, MatchingRegion.BOTH)) {
                String browser = "Baidu Video Search";
                res = new UserAgentDetectionResult(new Device("",DeviceType.BOT,Brand.BAIDU,"Video Search"),
                                                   new Browser(Brand.BAIDU,BrowserFamily.CRAWLER,browser, browser),
                                                   new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
            } else if (context.consume("Baiduspider-news", MatchingType.BEGINS, MatchingRegion.BOTH)) {
                String browser = "Baidu News Search";
                res = new UserAgentDetectionResult(new Device("",DeviceType.BOT,Brand.BAIDU,"News Search"),
                                                   new Browser(Brand.BAIDU,BrowserFamily.CRAWLER,browser, browser),
                                                   new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
            } else if (context.consume("Baiduspider-favo", MatchingType.BEGINS, MatchingRegion.BOTH)) {
                String browser = "Baidu Baidu collection";
                res = new UserAgentDetectionResult(new Device("",DeviceType.BOT,Brand.BAIDU,"Baidu collection"),
                                                   new Browser(Brand.BAIDU,BrowserFamily.CRAWLER,browser, browser),
                                                   new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
            } else if (context.consume("Baiduspider-cpro", MatchingType.BEGINS, MatchingRegion.BOTH)) {
                String browser = "Baidu Union " + getVersionNumber(context.getUA(),pos+16);
                res = new UserAgentDetectionResult(new Device("",DeviceType.BOT,Brand.BAIDU,"Baidu Union"),
                                                   new Browser(Brand.BAIDU,BrowserFamily.CRAWLER,browser, browser),
                                                   new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
            } else if (context.consume("Baiduspider-ads", MatchingType.BEGINS, MatchingRegion.BOTH)) {
                String browser = "Baidu Business Search " + getVersionNumber(context.getUA(),pos+15);
                res = new UserAgentDetectionResult(new Device("",DeviceType.BOT,Brand.BAIDU,"Business Search"),
                                                   new Browser(Brand.BAIDU,BrowserFamily.CRAWLER,browser, browser),
                                                   new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
            } else if ((ver=context.getcVersionAfterPattern("Baiduspider/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) != null) {
                String browser = "Baidu Web crawler " + ver;
                res = new UserAgentDetectionResult(new Device("",DeviceType.BOT,Brand.BAIDU,"Web crawler"),
                                                   new Browser(Brand.BAIDU,BrowserFamily.CRAWLER,browser, browser),
                                                   new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
            } else if (context.consume("Baiduspider", MatchingType.BEGINS, MatchingRegion.BOTH)) {
                String browser = "Baidu Web crawler";
                res = new UserAgentDetectionResult(new Device("",DeviceType.BOT,Brand.BAIDU,"Web crawler"),
                                                   new Browser(Brand.BAIDU,BrowserFamily.CRAWLER,browser, browser),
                                                   new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
            }


            if (res !=null) {
                consumeUrlAndMozilla(context,"http://");
                return res;
            }
        } else

            // Yandex bots
            if (null != (ver=context.getcToken("YandexBot/", MatchingType.BEGINS, MatchingRegion.BOTH)) || // main indexing robot;
                    null != (ver=context.getcToken("Yandex/", MatchingType.BEGINS, MatchingRegion.REGULAR)) || // Yandex.Image indexer;
                    null != (ver=context.getcToken("YandexImages/", MatchingType.BEGINS, MatchingRegion.BOTH)) || // Yandex.Image indexer;
                    null != (ver=context.getcToken("YandexVideo/", MatchingType.BEGINS, MatchingRegion.BOTH)) || // Yandex.Video indexer;
                    null != (ver=context.getcToken("YandexMedia/", MatchingType.BEGINS, MatchingRegion.BOTH)) || // robot indexing multimedia data;
                    null != (ver=context.getcToken("YandexBlogs/", MatchingType.BEGINS, MatchingRegion.BOTH)) || // blog search robot, indexing post comments;
                    null != (ver=context.getcToken("YandexFavicons/", MatchingType.BEGINS, MatchingRegion.BOTH)) || //  favicon indexing robot;
                    null != (ver=context.getcToken("YandexWebmaster/", MatchingType.BEGINS, MatchingRegion.BOTH)) || //  a robot that has been directed to a page through the
                    null != (ver=context.getcToken("YandexPagechecker/", MatchingType.BEGINS, MatchingRegion.BOTH)) || // a robot that validates the micro markup of a page using the "?" form;
                    null != (ver=context.getcToken("YandexImageResizer/", MatchingType.BEGINS, MatchingRegion.BOTH)) || //  mobile services robot;
                    null != (ver=context.getcToken("YandexDirect/", MatchingType.BEGINS, MatchingRegion.BOTH)) || // robot indexing pages of sites belonging to the Yandex Advertising Network;
                    null != (ver=context.getcToken("YandexDirect/", MatchingType.BEGINS, MatchingRegion.BOTH)) || // Yandex.Direct robot. This checks the accuracy of an advertised link before moderation;
                    null != (ver=context.getcToken("YandexMetrika/", MatchingType.BEGINS, MatchingRegion.BOTH)) || //  Yandex.Metrica robot;
                    null != (ver=context.getcToken("YandexNews/", MatchingType.BEGINS, MatchingRegion.BOTH)) || // Yandex.News robot;
                    null != (ver=context.getcToken("YandexCatalog/", MatchingType.BEGINS, MatchingRegion.BOTH)) || // Yandex.Catalog robot. If a site is offline for several days, it is removed from Catalog. As soon as the site comes online, it will automatically begin to appear in Catalog again.
                    null != (ver=context.getcToken("YandexAntivirus/", MatchingType.BEGINS, MatchingRegion.BOTH)) || //  an antivirus robot that checks websites for the presence of malicious code.
                    null != (ver=context.getcToken("YandexZakladki/", MatchingType.BEGINS, MatchingRegion.BOTH)) || // a robot used to verify the availability of pages added to Yandex.Bookmarks;
                    null != (ver=context.getcToken("YandexMarket/", MatchingType.BEGINS, MatchingRegion.BOTH))) { // Yandex.Market robot.
                String[]vv = ver.split("/");
                consumeUrlAndMozilla(context,"http://");
                context.consume("Win16", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
                context.consume("[HI]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
                context.consume("m", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                context.consume("P", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                context.consume("MirrorDetector", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
                return new UserAgentDetectionResult(new Device("",DeviceType.BOT,Brand.YANDEX,"Web crawler"),
                                                    new Browser(Brand.BAIDU,BrowserFamily.CRAWLER,(vv[0] + " " + vv[1]).trim(), "n/a"),
                                                    new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));

                // Sogou bots

            } else if ((multi = context.getcNextTokens(new Matcher[] {new Matcher("Sogou", MatchingType.EQUALS),
                new Matcher("web", MatchingType.EQUALS),
                new Matcher("spider/", MatchingType.BEGINS)
            },
        MatchingRegion.REGULAR)) != null) {
            String browser = "Sogou Web Spider " + multi[2].substring(7);
            context.consume("+http://", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.OTHER,"Sogou Web Spider"),
                       new Browser(Brand.SOGOU,BrowserFamily.CRAWLER,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"),
                       getLocale(context));
        }
        else if ((multi = context.getcNextTokens(new Matcher[] {new Matcher("Sogou", MatchingType.EQUALS),
                 new Matcher("Pic", MatchingType.EQUALS),
                 new Matcher("Spider/", MatchingType.BEGINS)
        },
        MatchingRegion.REGULAR)) != null) {
            String browser = "Sogou Picture Spider " + multi[2].substring(7);
            context.consume("+http://", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.OTHER,"Sogou Picture Spider"),
                       new Browser(Brand.SOGOU,BrowserFamily.CRAWLER,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"),
                       getLocale(context));
        }


        // MISC BOTS

        else if (context.consume("TencentTraveler", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            context.consumeAllTokens();
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.SPAMBOT,Brand.UNKNOWN,"Tencent Traveler"),
                       new Browser(Brand.UNKNOWN,BrowserFamily.CRAWLER,"Rencent Traveler",""),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));

        } else if (context.consume("Ask Jeeves", MatchingType.BEGINS, MatchingRegion.BOTH) ||
                   context.consume("Teoma/", MatchingType.BEGINS, MatchingRegion.BOTH)) {
            String browser = "Ask Jeeves Bot (ex Teoma)";
            String bdesc = browser;
            consumeUrlAndMozilla(context,"http://");
            context.consume("@", MatchingType.CONTAINS, MatchingRegion.PARENTHESIS);
            context.consume("Question and Answer Search", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume("Mozilla/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            context.consume("Jeeves", MatchingType.EQUALS, MatchingRegion.BOTH);
            ver = context.getcVersionAfterPattern("Teoma/Nutch-", MatchingType.BEGINS, MatchingRegion.REGULAR);
            if (ver != null) {
                bdesc = "Nutch " + ver;
            }

            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.ASK,"Ask Jeeves web search bot"),
                       new Browser(Brand.ASK,BrowserFamily.CRAWLER,bdesc, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));

        } else if (context.consume("ia_archiver", MatchingType.BEGINS, MatchingRegion.BOTH)) {
            String browser = "Alexa crawler";
            context.ignoreAllTokens();
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.AMAZON,"Amazon's Alexa web crawler "),
                       new Browser(Brand.AMAZON,BrowserFamily.CRAWLER,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));

        } else if ((multi = context.getcNextTokens(new Matcher[] {new Matcher("VoilaBot", MatchingType.EQUALS),
            new Matcher("BETA", MatchingType.EQUALS),
            new Matcher("^[0-9\\.]+$", MatchingType.REGEXP)
        },
        MatchingRegion.REGULAR)) != null) {
            String browser = "Voila Bot BETA " + multi[2];
            consumeUrlAndMozilla(context,"http://");
            context.consume("@", MatchingType.CONTAINS, MatchingRegion.PARENTHESIS);
            consumeRegularWindowsGarbage(context);

            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.ORANGE,"Voila Bot"),
                       new Browser(Brand.ORANGE,BrowserFamily.CRAWLER,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"),
                       getLocale(context));

        }
        else if ((ver=context.getcVersionAfterPattern("Twiceler-", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) != null) {
            String browser = "Twiceler " + ver;
            consumeUrlAndMozilla(context,"http://");
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.CUILL,"Twiceler"),
                       new Browser(Brand.CUILL,BrowserFamily.CRAWLER,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        } else if ((ver=context.getcVersionAfterPattern("emefgebot/", MatchingType.BEGINS, MatchingRegion.BOTH)) != null) {
            consumeUrlAndMozilla(context,"http://");
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.OTHER,"emefge bot"),
                       new Browser(Brand.CUILL,BrowserFamily.CRAWLER,"", ""),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        } else if ((ver=context.getcVersionAfterPattern("YodaoBot/", MatchingType.BEGINS, MatchingRegion.BOTH)) != null ||
                   (ver=context.getcVersionAfterPattern("+YodaoBot/", MatchingType.BEGINS, MatchingRegion.BOTH)) != null) {
            consumeUrlAndMozilla(context,"http://");
            consumeUrlAndMozilla(context,"+http://");
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.OTHER,"Yodao Bot"),
                       new Browser(Brand.OTHER,BrowserFamily.CRAWLER,"", ""),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        } else if ((ver=context.getcVersionAfterPattern("YodaoBot-Image/", MatchingType.BEGINS, MatchingRegion.BOTH)) != null) {
            consumeUrlAndMozilla(context,"http://");
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.OTHER,"Yodao Image Bot"),
                       new Browser(Brand.OTHER,BrowserFamily.CRAWLER,"", ""),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        } else if ((ver=context.getcVersionAfterPattern("YodaoBot-Mobile/", MatchingType.BEGINS, MatchingRegion.BOTH)) != null) {
            while (context.consume("",MatchingType.CONTAINS, MatchingRegion.BOTH));
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.OTHER,"Yodao Mobile Bot"),
                       new Browser(Brand.OTHER,BrowserFamily.CRAWLER,"", ""),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        } else if (context.getcNextTokens(new Matcher[] {new Matcher("Speedy",MatchingType.EQUALS),
        }, MatchingRegion.REGULAR) != null ||
        context.consume("Speedy Spider",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            while (context.consume("",MatchingType.CONTAINS, MatchingRegion.BOTH));
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.OTHER,"Speedy Spider"),
                       new Browser(Brand.OTHER,BrowserFamily.CRAWLER,"", ""),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        }
        else if (context.consume("spbot/",MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
            while (context.consume("",MatchingType.CONTAINS, MatchingRegion.BOTH));
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.OTHER,"seoprofiler.com crawler"),
                       new Browser(Brand.OTHER,BrowserFamily.CRAWLER,"", ""),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        } else if (context.consume("FSPBot/",MatchingType.BEGINS, MatchingRegion.REGULAR)) {
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.OTHER,"FSPBot"),
                       new Browser(Brand.OTHER,BrowserFamily.ROBOT,"", ""),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        } else if (context.consume("SiteSucker/",MatchingType.BEGINS, MatchingRegion.REGULAR)) {
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.OTHER,"SiteSucker"),
                       new Browser(Brand.OTHER,BrowserFamily.ROBOT,"", ""),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        } else if (context.consume("360Spider",MatchingType.EQUALS, MatchingRegion.REGULAR)) {
            context.ignoreAllTokens();
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.OTHER,"360 Spider"),
                       new Browser(Brand.OTHER,BrowserFamily.ROBOT,"", ""),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        } else if (context.consume("FlipboardProxy/",MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
            context.ignoreAllTokens();
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.OTHER,"FlipBoard proxy"),
                       new Browser(Brand.OTHER,BrowserFamily.ROBOT,"", ""),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));

        } else if (context.consume("Exabot/",MatchingType.BEGINS, MatchingRegion.BOTH) || context.consume("Exabot-Images/",MatchingType.BEGINS, MatchingRegion.BOTH) || context.consume("Exabot-Test/",MatchingType.BEGINS, MatchingRegion.BOTH)) {
            consumeUrlAndMozilla(context,"http://");
            context.consume("BiggerBetter", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.OTHER,"Exalead Bot"),
                       new Browser(Brand.OTHER,BrowserFamily.CRAWLER,"", ""),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        } else if (context.consume("MRSPUTNIK (OW )?([0-9], )+[0-9]+( [SH]W)?",MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) {
            context.ignoreAllTokens();
            String browser = "Spam Bot";
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.OTHER,"MRS PUTNIK"),
                       new Browser(Brand.OTHER,BrowserFamily.CRAWLER,browser,browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        } else if (context.consume("ips-agent",MatchingType.EQUALS, MatchingRegion.BOTH)) {
            context.consume("BlackBerry",MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("Profile/MIDP",MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("Configuration/",MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("VendorID/",MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("Mozilla/5.0",MatchingType.EQUALS, MatchingRegion.REGULAR);
            context.consume("Gecko/",MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("Firefox/",MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("X11",MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume("Ubuntu",MatchingType.BEGINS, MatchingRegion.BOTH);
            context.consume("Fedora",MatchingType.BEGINS, MatchingRegion.BOTH);
            context.consume("Linux i686",MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            context.consume("rv:",MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            context.consume("lucid",MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume("U",MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume("en-US",MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.OTHER,"VeriSign Bot"),
                       new Browser(Brand.OTHER,BrowserFamily.ROBOT,"", ""),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        } else if (context.consume("ichiro/mobile goo",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            while (context.consume(".*",MatchingType.REGEXP, MatchingRegion.BOTH));
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.OTHER,"Goo crawler"),
                       new Browser(Brand.OTHER,BrowserFamily.ROBOT,"", ""),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        }


        /*else if ((pos=userAgent.indexOf("webcrawler/"))>-1) {
              String browser = "WebCrawler " + getVersionNumber(userAgent,pos+11);
            } else // The following two bots don't have any version number in their User-Agent strings.
              if ((pos=userAgent.indexOf("inktomi"))>-1) {
              String browser = "Inktomi";
            } else if ((pos=userAgent.indexOf("teoma"))>-1) {
              String browser = "Teoma";
            }*/ else if ((ver=context.getcVersionAfterPattern("Yahoo! Slurp", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) != null) {
            String browser = "Yahoo! Slurp " + ver;
            browser = browser.trim();
            consumeUrlAndMozilla(context,"http://");
            return new UserAgentDetectionResult(
                       new Device("",DeviceType.BOT,Brand.YAHOO,"Slurp (Web crawler)"),
                       new Browser(Brand.YAHOO,BrowserFamily.ROBOT,browser, browser),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"Bot","Bot"));
        }

        return null;
    }

    static boolean isKindle(UserAgentContext context, boolean expectConsumed) {
        MatchingRegion region = (expectConsumed)?MatchingRegion.CONSUMED:MatchingRegion.PARENTHESIS;
        return context.consume("KFTT", MatchingType.BEGINS, region) ||
               context.consume("KFOTE", MatchingType.BEGINS, region) ||
               context.consume("KFJWI", MatchingType.BEGINS, region);
    }

    static OS getOS(UserAgentContext context) {
        String userAgent = context.getUA();
        OS res = null;
        int pos;
        String ver;
        String[] mt=null;
        if (context.contains("Series40", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
            ver=context.getcVersionAfterPattern("Series40/", MatchingType.BEGINS,MatchingRegion.PARENTHESIS);
            if (ver == null) ver = "";
            res = new OS(Brand.NOKIA,OSFamily.SERIES40,"Series40",ver);
            context.consume("Series40", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
        } else if ((ver=context.getcVersionAfterPattern("SymbianOS/", MatchingType.BEGINS, MatchingRegion.BOTH)) != null ||
                   (ver=context.getcVersionAfterPattern("Symbian/", MatchingType.BEGINS, MatchingRegion.BOTH)) != null ||
                   context.contains("Series60/", MatchingType.BEGINS, MatchingRegion.REGULAR) ||
                   context.contains("S60/", MatchingType.BEGINS, MatchingRegion.BOTH) ||
                   context.contains("Symbian OS", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            if (ver == null) ver = "";
            res = new OS(Brand.NOKIA,OSFamily.SYMBIAN,"Symbian OS",ver);
            ver=context.getcVersionAfterPattern("Series60/", MatchingType.BEGINS,MatchingRegion.BOTH);
            if (ver != null) {
                res.version += " Series60 " + ver;
            } else {
                ver=context.getcVersionAfterPattern("S60/", MatchingType.BEGINS,MatchingRegion.BOTH);
                if (ver != null) res.version += " Series60 " + ver;
            }
            if (context.consume("Symbian OS", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                context.consume("[0-9]{3}[0-9]?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
            }
            res.version = res.version.trim();
        } else if (context.consume("MeeGo", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res = new OS(Brand.NOKIA,OSFamily.MEEGO,"MeeGo","");
        } else if ((ver=context.getcVersionAfterPattern("Bada/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) != null) {
            res = new OS(Brand.SAMSUNG,OSFamily.BADA,"Bada",ver);

            context.consume("[A-Z]{1,2}VGA", MatchingType.REGEXP, MatchingRegion.REGULAR);
            context.consume("SMM-MMS/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("NexPlayer/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("SAMSUNG", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume("OPN-B", MatchingType.EQUALS, MatchingRegion.REGULAR);

        } else if ((ver = context.getcVersionAfterPattern("Windows Phone OS", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_MOBILE,"Windows Phone OS",ver);
        } else if ((ver = context.getcVersionAfterPattern("Windows Phone", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_MOBILE,"Windows Phone", ver);
            ver = context.getcVersionAfterPattern("Windows Phone", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            if (ver != null && ver.length()>res.version.length()) // SonyEricsson UAs include the version twice. Get the most precise one.
                res.version = ver;
            context.consume("Touch", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume("ARM", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume("Windows NT", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
        } else if (context.consume("Windows-NT", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Win","NT");
        } else if (context.contains("Windows NT", MatchingType.CONTAINS, MatchingRegion.PARENTHESIS)) {
            if (context.consume("Windows NT 5.1", MatchingType.CONTAINS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","XP");
                while (context.consume("uE v7", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)); // Don't really know what that is, but some XP UAs show it.
                boolean sp2 = false;
                if (context.consume("SV1", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                    res.version += " SP2";
                    sp2 = true;
                }
                if ((ver=context.getcVersionAfterPattern("Media Center PC ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                    if (ver.equals("2.7") || ver.equals("2.8"))
                        res.version += " Media Center 2004";
                    else if (ver.equals("3.0") || ver.equals("3.1") || ver.equals("4.0")) {
                        res.version += " Media Center 2005";
                        if (ver.equals("3.1")) res.version += " (update rollup 1)";
                        if (ver.equals("4.0")) res.version += " (update rollup 2)";
                        if (!sp2) {
                            res.version += " SP2";
                            sp2 = true;
                        }
                    } else {
                        try {
                            if (Float.parseFloat(ver) < 2.7)
                                res.version += " Media Center 2002";
                        } catch (Exception e) {
                            res.version += " Media Center " + ver;
                        }
                    }
                    context.consume("Media Center PC ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS); // Sometimes present more than once
                }
            } else if (context.consume("Windows NT 6.0", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                context.consume("SV1", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","Vista");
                if ((ver=context.getcVersionAfterPattern("Media Center PC ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                    if (ver.equals("5.0"))
                        res.version += " Media Center";
                    else if (ver.equals("5.1"))
                        res.version += " Media Center TV Pack";
                    else
                        res.version += " Media Center " + ver;
                    context.consume("Media Center PC ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS); // Sometimes present more than once
                }
            } else if (context.consume("Windows NT 6.1", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                context.consume("SV1", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","7");
                if ((ver=context.getcVersionAfterPattern("Media Center PC ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                    if (ver.equals("6.0"))
                        res.version += " Media Center";
                    else
                        res.version += " Media Center " + ver;
                    context.consume("Media Center PC ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS); // Sometimes present more than once
                }
            } else if (context.consume("Windows NT 6.2", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","8");
                if (context.consume("ARM", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                    res.version += " RT";
                }
                context.consume("Touch", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            } else if (context.consume("Windows NT 5.0", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","2000");
                if (context.contains("Windows NT 5.01", MatchingType.BEGINS, MatchingRegion.CONSUMED)) res.version += " SP1";
            } else if (context.consume("Windows NT 5.2", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","2003 or XP x64 Edition");
                context.consume("SV1", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            } else if (context.consume("Windows NT( )?4.0", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","NT4");
            } else if (context.consume("Windows NT", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Win","NT");
            } else
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"WinNT?","WinNT?");
            /*if ((pos=userAgent.indexOf("Tablet PC"))>-1 && userAgent.indexOf("Touch")>-1)
                res.version += " Tablet PC " + getVersionNumber(userAgent, pos+9);*/
        } else if (context.consume("Windows XP 5.1", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","XP");
        } else if (context.consume("Windows 2003 5.2", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","2003 or XP x64 Edition");
        } else if (context.consume("Windows 7 6.1", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","7");
        } else if (context.consume("Windows Vista 6.0", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","Vista");
        } else if (context.consume("Windows Vista 6.1", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","Vista or 7");
        } else if (context.consume("Windows Me 4.90", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS,"Windows","Millenium Edition (ME)");
        } else if (context.consume("Win3.1", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS,"Windows","3.11");
        } else if (context.contains("Opera", MatchingType.EQUALS, MatchingRegion.REGULAR) && context.consume("Windows ME", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS,"Windows","Millenium Edition (ME)");
        } else if (context.contains("Win",MatchingType.BEGINS, MatchingRegion.PARENTHESIS)
                   && !context.contains("X11",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            // Some User-Agents include two references to Windows
            // Ex: Mozilla/5.0 (Windows; U; Win98; en-US; rv:1.5)
            boolean foundWindows = context.consume("Windows",MatchingType.EQUALS, MatchingRegion.PARENTHESIS);

            if (context.getcNextTokens(new Matcher[] {new Matcher("Windows 98",MatchingType.EQUALS),
                new Matcher("Win 9x 4.90",MatchingType.EQUALS)
            }, MatchingRegion.PARENTHESIS) != null ||
            context.consume("Win 9x 4.90",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS,"Windows","Millenium Edition (ME)");
            }
            else if (context.consume("Windows 98",MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                if (context.contains("PalmSource/",MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                    res = new OS(Brand.PALM,OSFamily.OTHER,"Palm OS","");
                } else {
                    res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS,"Windows","98");
                }
            } else if (context.consume("Windows_98",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS,"Windows","98");
            } else if (context.consume("Windows 2000",MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","2000");
            } else if (context.consume("Windows 95",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS,"Windows","95");
            } else if (context.consume("Windows 9x",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS,"Windows","9x");
            } else if (context.consume("Windows CE",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_MOBILE,"Windows","CE");
            } else if (context.getcNextTokens(new Matcher[] {new Matcher("Windows Mobile", MatchingType.EQUALS),
                new Matcher("WCE",MatchingType.EQUALS)
            }, MatchingRegion.PARENTHESIS) != null) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_MOBILE,"Windows","CE");
            }
            else if (context.consume("Windows 3.11",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS,"Windows","3.11");
            } else if (context.consume("Windows 3.1",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS,"Windows","3.1");
            } else if (context.consume("Win98",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS,"Windows","98");
            } else if (context.consume("Win31",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS,"Windows","3.1");
            } else if (context.consume("Win95",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS,"Windows","95");
            } else if (context.consume("Win 9x",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS,"Windows","9x");
            } else if (context.consume("WinNT4.0",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","NT4");
            } else if (context.consume("WinNT",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","NT");
            } else if (context.consume("Windows",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS,"Windows","Unknown");
            } else if (context.consume("Win",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS,"Windows","Unknown");
            } else
                // Should not happen at this point
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS,"Windows","Unknown");

            if (res.family == OSFamily.WINDOWS_MOBILE) {
                context.consume("OpVer [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
                context.consume("PPC;", MatchingType.EQUALS, MatchingRegion.REGULAR);
                context.getcNextTokens(new Matcher[] {new Matcher("OpVer", MatchingType.EQUALS),
                                           new Matcher("[0-9\\.]+",MatchingType.REGEXP)
                }, MatchingRegion.REGULAR);
            }
        } else if ((ver = context.getcVersionAfterPattern("Intel Mac OS X", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            res = new OS(Brand.APPLE,OSFamily.MACOSX,"Intel Mac OS X",ver);
        } else if (context.contains("like Mac OS X", MatchingType.ENDS, MatchingRegion.PARENTHESIS) &&
                   ((ver = context.getcVersionAfterPattern("CPU OS ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null ||
                    (ver = context.getcVersionAfterPattern("CPU iPhone OS ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null)) {
            res = new OS(Brand.APPLE,OSFamily.IOS,"iOS",ver);
        } else if ((ver = context.getcVersionAfterPattern("Mac OS X", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null ||
                   (ver = context.getcVersionAfterPattern("PPC Mac OS X", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            res = new OS(Brand.APPLE,OSFamily.MACOSX,"Mac OS X",ver);
        } else if ((ver = context.getcVersionAfterPattern("Android", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            context.consume("Linux", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            context.consume("Build/GINGERBREAD", MatchingType.EQUALS, MatchingRegion.BOTH);
            if (isKindle(context, false)) {
                // Code duplicated
                res = new OS(Brand.AMAZON,OSFamily.ANDROID,"Amazon Android",ver);
            } else {
                res = new OS(Brand.GOOGLE,OSFamily.ANDROID,"Android",ver);
                if ((ver = context.getcVersionAfterPattern("CyanogenMod-", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                    res.version += " (CyanogenMod "+ver+")";
                }
            }
        } else if (context.consume("Mac_PowerPC", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res = new OS(Brand.APPLE,OSFamily.MACOS,"Mac OS PPC","");
        } else if (context.consume("Macintosh PPC", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res = new OS(Brand.APPLE,OSFamily.MACOS,"Mac OS PPC","");
        } else if (context.contains("Macintosh", MatchingType.EQUALS, MatchingRegion.PARENTHESIS) &&
                   context.consume("PPC", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res = new OS(Brand.APPLE,OSFamily.MACOS,"Mac OS PPC","");
            context.consume("Macintosh", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        } else if ((ver = context.getcVersionAfterPattern("CrOS", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) != null) {
            if (ver.contains(" ")) ver = ver.split(" ")[1];
            context.consume("X11", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            res = new OS(Brand.GOOGLE,OSFamily.CHROMEOS,"Chrome OS",ver);
        } else if ((ver = context.getcVersionAfterPattern("FreeBSD", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) != null) {
            res = new OS(Brand.UNKNOWN,OSFamily.BSD,"FreeBSD",ver);
        } else if ((ver = context.getcVersionAfterPattern("OpenBSD", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) != null) {
            res = new OS(Brand.UNKNOWN,OSFamily.BSD,"OpenBSD",ver);
        } else if ((ver = context.getcToken(".*el([0-9]+)\\.centos.*", MatchingType.REGEXP, MatchingRegion.BOTH))!=null) {
            java.util.regex.Matcher m = java.util.regex.Pattern.compile(".*el([0-9]+)\\.centos.*").matcher(ver);
            ver = m.find() ? "EL"+m.group(1) : "";
            res = new OS(Brand.LINUX,OSFamily.LINUX,"CentOS", ver);
        } else if ((ver=context.getcVersionAfterPattern("hpwOS/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            res = new OS(Brand.HP,OSFamily.WEBOS,"WebOS",ver);
            context.consume("Linux", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
        } else if ((ver=context.getcVersionAfterPattern("webOS/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            res = new OS(Brand.PALM,OSFamily.WEBOS,"WebOS",ver);
            context.consume("Linux", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
        } else if (context.contains("Linux", MatchingType.CONTAINS, MatchingRegion.BOTH)) {
            if (isKindle(context,false)) {
                // Code duplicated
                res = new OS(Brand.AMAZON,OSFamily.ANDROID,"Amazon Android","");
                context.consume("Linux", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            } else {
                ver = context.getcVersionAfterPattern("Linux", MatchingType.CONTAINS, MatchingRegion.BOTH);
                if (ver == null) ver = "";
                String detail = ver;
                String med = "Linux";
                if ((ver = context.getcVersionAfterPattern("Ubuntu/", MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                    med = "Ubuntu";
                    detail = ver;
                    context.consume("hardy", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                    context.consume("gutsy", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                    context.consume("maverick", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                    context.consume("lucid", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                    context.consume("intrepid", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                    context.consume("karmic", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                    context.consume("jaunty", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                } else if ((ver = context.getcVersionAfterPattern("Ubuntu-feisty", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) != null) {
                    med = "Ubuntu";
                    detail = "7.04";
                } else if (context.consume("karmic", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                    med = "Ubuntu";
                    detail = "9.10";
                    context.getcNextTokens(new Matcher[] {new Matcher("Ultimate", MatchingType.EQUALS),
                                               new Matcher("Edition/",MatchingType.BEGINS)
                    }, MatchingRegion.REGULAR);
                } else if ((ver = context.getcVersionAfterPattern("Ubuntu-edgy", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) != null) {
                    med = "Ubuntu";
                    detail = "6.10";
                } else if ((mt = context.getcNextTokens(new Matcher[] {new Matcher("Kubuntu", MatchingType.EQUALS),
                    new Matcher("[\\.0-9]+",MatchingType.REGEXP)
                }, MatchingRegion.REGULAR)) != null ||
                (ver = context.getcVersionAfterPattern("Kubuntu package ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) != null ||
                context.consume("Kubuntu", MatchingType.EQUALS, MatchingRegion.BOTH)) {
                    if (mt != null) ver = mt[1];
                    if (ver == null) ver = "";
                    med = "Ubuntu";
                    detail = ("Kubuntu " + ver).trim();
                    context.consume("Dapper", MatchingType.EQUALS, MatchingRegion.REGULAR);
                }
                else if ((ver = context.getcVersionAfterPattern("Fedora", MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                    med = "Fedora"; // Used to get the version through ver but it looks like it's the version of the browser, not Fedora's
                    detail = "";
                } else if ((ver = context.getcVersionAfterPattern("openSUSE/", MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                    med = "openSuSE";
                    detail = ver;
                } else if ((ver = context.getcVersionAfterPattern("Mint/", MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                    med = "Mint";
                    detail = ver;
                    context.consume("Helena", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                } else if ((ver = context.getcVersionAfterPattern("PCLinuxOS ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) != null) {
                    med = "PCLinuxOS";
                    detail = ver;
                } else if (context.consume("Mandriva", MatchingType.BEGINS, MatchingRegion.REGULAR)) {
                    context.consume("20[01][0-9]\\.[0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
                    ver = context.getcVersionAfterPattern("Linux/", MatchingType.BEGINS, MatchingRegion.CONSUMED);
                    if (ver != null) {
                        String[]vs = ver.split("-");
                        if (vs.length>0) ver = vs[0];
                        detail = ver;
                    }
                    med = "Mandriva";
                } else if ((ver = context.getcVersionAfterPattern("SUSE/", MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                    String[]vs = ver.split("-");
                    if (vs.length==2) ver = vs[1];
                    med = "SuSE";
                    detail = ver;
                } else if ((ver = context.getcVersionAfterPattern("SUSE", MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                    med = "SuSE";
                } else if (context.consume("Gentoo/", MatchingType.BEGINS, MatchingRegion.BOTH) ||
                           context.consume("Gentoo", MatchingType.EQUALS, MatchingRegion.BOTH)) {
                    med = "Gentoo";
                    ver = "";
                } else if (detail.indexOf("-gentoo-")>-1) {
                    med = "Gentoo";
                } else if (context.consume("Debian/squeeze", MatchingType.BEGINS, MatchingRegion.REGULAR)) {
                    med = "Debian";
                    detail="Squeeze";
                    context.consume("[0-9]\\.[0-9]+\\.[0-9]+-[0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
                } else if (context.consume("Debian-", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                    med = "Debian";
                    context.consume("Debian package", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
                } else if (context.consume("Debian package", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) ||
                           context.consume("Debian", MatchingType.BEGINS, MatchingRegion.BOTH) ||
                           context.contains("Debian", MatchingType.BEGINS, MatchingRegion.CONSUMED)) {
                    med = "Debian";
                    detail = "";
                } else if ((ver = context.getcVersionAfterPattern("MEPIS-", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) != null) {
                    med = "MEPIS";
                    detail = ver;
                } else if ((ver = context.getcVersionAfterPattern("MEPIS", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) != null) {
                    med = "MEPIS";
                    detail = "";
                } else if ((ver = context.getcVersionAfterPattern("CentOS/", MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                    med = "CentOS";
                    detail = "";
                } else if ((ver = context.getcVersionAfterPattern("Ubuntu/", MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                    med = "Ubuntu";
                    detail = ver;
                } else if ((ver = context.getcVersionAfterPattern("Jolicloud/", MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                    med = "Joli OS";
                    detail = ver;
                } else if ((mt = context.getcNextTokens(new Matcher[] {new Matcher("Joli", MatchingType.EQUALS),
                    new Matcher("OS/[0-9\\.]+",MatchingType.REGEXP)
                }, MatchingRegion.REGULAR))!=null) {
                    med = "Joli OS";
                    detail = mt[1].substring(3);
                }
                else if ((ver = context.getcVersionAfterPattern("Pardus/", MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                    med = "Pardus";
                    detail = ver;
                } else if (context.consume("Ubuntu", MatchingType.EQUALS, MatchingRegion.BOTH)) {
                    med = "Ubuntu";
                    detail = "";
                }
                res = new OS(Brand.LINUX,OSFamily.LINUX,med,detail);
            }
        } else if (context.consume("CentOS", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res = new OS(Brand.LINUX,OSFamily.LINUX,"CentOS","");
        } else if ((ver = context.getcVersionAfterPattern("GNU Fedora fc ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) != null) {
            res = new OS(Brand.LINUX,OSFamily.LINUX,"Linux","Fedora " + ver);
        } else if ((ver = context.getcToken("NetBSD", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) != null) {
            String[]vv = ver.split(" ");
            if (vv.length == 3) {
                ver = vv[1];
            } else ver = "";
            res = new OS(Brand.UNKNOWN,OSFamily.BSD,"NetBSD",ver);
        } else if (context.consume("Unix", MatchingType.EQUALSIGNORECASE, MatchingRegion.BOTH)) {
            res = new OS(Brand.UNKNOWN,OSFamily.UNIX,"","");
        } else if ((ver = context.getcVersionAfterPattern("SunOS", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            context.consume("I",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            if (context.consume("Nexenta package", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))
                ver += " Nexenta";
            res = new OS(Brand.SUN, OSFamily.UNIX, "SunOS", ver);
            context.consume(".*sun4[umv]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        } else if ((ver = context.getcToken("IRIX ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) != null ||
                   (ver = context.getcToken("IRIX64 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) != null ||
        (mt = context.getcNextTokens(new Matcher[] {new Matcher("IRIX", MatchingType.EQUALS),
            new Matcher("(64 )?([0-9\\.]+ )?IP[0-9]+",MatchingType.REGEXP)
        }, MatchingRegion.PARENTHESIS)) != null) {
            if (ver == null) ver = mt[1];
            ver = ver.substring(ver.indexOf(" "));
            res = new OS(Brand.SGI,OSFamily.UNIX,"IRIX",ver);
            context.consume("I", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        }
        else  if (context.consume("OS/2", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            ver=context.getcVersionAfterPattern("Warp ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            String OS = "";
            if (ver != null) {
                OS = "Warp " + ver;
            }
            res = new OS(Brand.IBM,OSFamily.OS2,"OS/2",OS);
        } else if (context.consume("BEOS", MatchingType.EQUALSIGNORECASE, MatchingRegion.PARENTHESIS) ||
                   context.consume("BeOS ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
            context.consume("BeOS ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            if (context.consume("Haiku BePC", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.HAIKU,OSFamily.BEOS,"Haiku","");
            } else {
                res = new OS(Brand.BE,OSFamily.BEOS,"BeOS","");
            }
        } else if ((ver = context.getcVersionAfterPattern("RISC OS", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            res = new OS(Brand.ACORN, OSFamily.RISC, "RISC OS", ver);
            context.consume("Acorn ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
        } else if (context.consume("SonyEricsson", MatchingType.BEGINS, MatchingRegion.REGULAR)) {
            res = new OS(Brand.SONY, OSFamily.OTHER, "SonyEricsson OS", "");
        } else if (context.consume("BlackBerry", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            ver = "";
            if (context.contains("AppleWebKit/", MatchingType.BEGINS, MatchingRegion.REGULAR))
                ver = context.getcVersionAfterPattern("Version/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            if (ver == null) ver = "";
            if (ver.length()>0) {
                if (!ver.matches("[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+")) ver = "";
            }
            res = new OS(Brand.RIM, OSFamily.BBOS, "BB OS", ver);
        } else if ((ver=context.getcToken("BlackBerry[0-9]+/[0-9\\.]+", MatchingType.REGEXP, MatchingRegion.REGULAR)) != null) {
            res = new OS(Brand.RIM, OSFamily.BBOS, "BB OS", ver.substring(ver.indexOf("/")+1));
        } else if ((ver=context.getcVersionAfterPattern("RIM Tablet OS", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) != null) {
            res = new OS(Brand.RIM, OSFamily.RIM_TABLET, "Tablet OS", ver);



        } else if ((ver=context.getcVersionAfterPattern("PlayStation Vita", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            res = new OS(Brand.SONY,OSFamily.PLAYSTATION,"PlayStation Vita",ver);
        } else if ((mt = context.getcNextTokens(new Matcher[] {new Matcher("PLAYSTATION 3", MatchingType.EQUALS),
            new Matcher("[0-9\\.]+",MatchingType.REGEXP)
        }, MatchingRegion.PARENTHESIS)) != null) {
            context.consume("Mozilla/5.0", MatchingType.EQUALS, MatchingRegion.REGULAR);
            res = new OS(Brand.SONY,OSFamily.PLAYSTATION,"PlayStation 3",mt[1]);
        }
        else if ((mt = context.getcNextTokens(new Matcher[] {new Matcher("PSP", MatchingType.EQUALS),
                 new Matcher("[0-9\\.]+",MatchingType.REGEXP)
        }, MatchingRegion.PARENTHESIS)) != null) {
            res = new OS(Brand.SONY,OSFamily.PLAYSTATION,"PlayStation Portable",mt[1]);
            context.consume("Mozilla/4.0", MatchingType.EQUALS, MatchingRegion.REGULAR);
        }
        else if ((ver=context.getcVersionAfterPattern("PLAYSTATION3", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            res = new OS(Brand.SONY,OSFamily.PLAYSTATION,"PlayStation 3",ver);
        } else if ((ver=context.getcVersionAfterPattern("PLAYSTATION 3", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            res = new OS(Brand.SONY,OSFamily.PLAYSTATION,"PlayStation 3",ver);
        } else if (context.consume("OpenVMS ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
            boolean X11 = context.consume("X11", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            res = new OS(Brand.DIGITAL_HP,OSFamily.OTHER,"Open VMS",X11?" X11 capable":"");
            context.consume("HP", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        } else if (context.consume("X11", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res = new OS(Brand.UNKNOWN,OSFamily.UNIX,"Unix-like","X11 capable");
            context.consume("I", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        } else if ((mt = context.getcNextTokens(new Matcher[] {new Matcher("Nintendo", MatchingType.EQUALS),
            new Matcher("Wii;",MatchingType.EQUALS)
        }, MatchingRegion.REGULAR)) != null) {
            res = new OS(Brand.NINTENDO,OSFamily.OTHER,"OS for Nintendo Wii","");
        }
        if (context.consume("Nintendo WiiU", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) {
            res = new OS(Brand.NINTENDO,OSFamily.OTHER,"OS for Nintendo WiiU","");
            context.consume("[0-9]{4}(\\-[0-9])?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        }
        if (context.consume("Nintendo Wii", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) {
            res = new OS(Brand.NINTENDO,OSFamily.OTHER,"OS for Nintendo Wii","");
            context.consume("[0-9]{4}(\\-[0-9])?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        } else if (context.consume("Nintendo DSi", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res = new OS(Brand.NINTENDO,OSFamily.OTHER,"OS for Nintendo DSi","");
        } else if (context.consume("Nintendo 3DS", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res = new OS(Brand.NINTENDO,OSFamily.OTHER,"OS for Nintendo 3DS","");
        }

        if (res == null) {
            res = new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"","");
        }

        if (res.family == OSFamily.WINDOWS_NT) {
            context.consume("Windows", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        }
        if (res.family == OSFamily.MACOS || res.family == OSFamily.MACOSX) {
            context.consume("Macintosh", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        }

        return res;
    }





    static String getVersionVersion(UserAgentContext context) {
        String ver;
        if ((ver=context.getcVersionAfterPattern("Version/",  MatchingType.BEGINS, MatchingRegion.BOTH))!=null)
            return ver;
        else
            return "";
    }

    static String getKHTMLVersion(UserAgentContext context) {
        try {
            String ver = context.getcVersionAfterPattern("KHTML/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            if (ver != null) return "KHTML " + ver;
            ver = context.getcVersionAfterPattern("KHTML/", MatchingType.BEGINS, MatchingRegion.CONSUMED);
            if (ver != null) return "KHTML " + ver;
            ver = context.getcVersionAfterPattern("Konqueror/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            if (ver != null) return "KHTML for Konqueror " + ver;
            ver = context.getcVersionAfterPattern("Konqueror/", MatchingType.BEGINS, MatchingRegion.CONSUMED);
            if (ver != null) return "KHTML for Konqueror " + ver;
            return "";
        } finally {
        }
    }

    static String getTridentVersion(UserAgentContext context, String ieWithVersion) {
        String tver = context.getcVersionAfterPattern("Trident/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
        if (tver != null) return "Trident " + tver;
        return "Trident for " + ieWithVersion;
    }

    static String getPrestoVersion(UserAgentContext context, String matched) {
        String ver;
        if ((ver=context.getcVersionAfterPattern("Presto/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            return "Presto " + ver;
        }
        if (matched != null) {
            return "Presto for Opera " + matched;
        }
        return "";
    }

    static String getWebkitVersion(UserAgentContext context) {
        try {
            String ver = context.getcVersionAfterPattern("AppleWebKit/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            if (ver != null) return "WebKit " + ver;
            ver = context.getcVersionAfterPattern("Safari/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            if (ver != null) return "WebKit " + ver;
            ver = context.getcVersionAfterPattern("KHTML/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            if (ver != null) return "KHTML " + ver;
            return "WebKit ?";
        } finally {
            consumeWebKitBullshit(context);
        }
    }

    static Browser getGecko(UserAgentContext context, String ver, OS os) {
        if (ver == null) ver = "";
        if (ver.length() > 8) ver = ver.substring(0,8);
        String gv = context.getcVersionAfterPattern("rv:", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
        if (gv == null) gv = ver;
        else gv = (gv + " " + ver).trim();
        Browser res = new Browser(Brand.MOZILLA, BrowserFamily.OTHER_GECKO,"Gecko-based",("Gecko " + gv).trim());
        if ((ver = context.getcVersionAfterPattern("Camino/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res.description="Camino "+ver;
            context.consume("like Firefox", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            context.ignore("MultiLang", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        } else if ((ver = context.getcVersionAfterPattern("Chimera/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res.description="Chimera "+ver;
        } else if ((ver = context.getcVersionAfterPattern("Iceweasel/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res.description="Iceweasel "+ver;
            context.consume("like Firefox", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
        } else if ((ver = context.getcVersionAfterPattern("IceCat/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            // The new IceWeasel
            res.description="IceCat "+ver;
            context.consume("like Firefox", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
        } else if ((ver = context.getcVersionAfterPattern("Firebird/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res.description="Firebird "+ver;
            context.consume("Mozilla",  MatchingType.EQUALS, MatchingRegion.REGULAR);
        } else if ((ver = context.getcVersionAfterPattern("Kazehakase/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            context.consume("Firefox/",  MatchingType.BEGINS, MatchingRegion.REGULAR);
            res.description="Kazehakase "+ver;
        } else if ((ver = context.getcVersionAfterPattern("Thunderbird/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res.description="Thunderbird "+ver;
        } else if ((ver = context.getcVersionAfterPattern("Phoenix/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res.description="Phoenix "+ver;
        } else if (os.family == OSFamily.WINDOWS &&
                   os.version.equals("98") &&
                   context.contains("N",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS) &&
                   context.contains("m18",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res.description="K-Meleon";
            context.consume("N",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume("m18",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        } else if ((ver = context.getcVersionAfterPattern("K-Meleon/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res.description="K-Meleon "+ver;
        } else if ((ver = context.getcVersionAfterPattern("Galeon/",  MatchingType.BEGINS, MatchingRegion.BOTH))!=null) {
            res.description="Galeon "+ver;
            context.consume("Firefox/", MatchingType.BEGINS, MatchingRegion.REGULAR);
        } else if ((ver = context.getcVersionAfterPattern("Epiphany/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            context.consume("Firefox/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            res.description="Epiphany "+ver;
        } else if ((ver = context.getcVersionAfterPattern("Flock/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            context.consume("Firefox/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            res.description="Flock "+ver;
        } else if ((ver = context.getcVersionAfterPattern("SeaMonkey/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res.description="SeaMonkey "+ver;
        } else if ((ver = context.getcVersionAfterPattern("Seamonkey-",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res.description="SeaMonkey "+ver;
        } else if ((ver = context.getcVersionAfterPattern("GranParadiso/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res.family=BrowserFamily.FIREFOX;
            res.description="GranParadiso " + ver + " (Firefox beta)";
            res.renderingEngine+=" (GranParadiso"+ver+")";
            context.consume("Firefox",MatchingType.BEGINS, MatchingRegion.REGULAR);
        } else if ((ver = context.getcVersionAfterPattern("Firefox/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            context.consume("Fennec/",MatchingType.BEGINS, MatchingRegion.REGULAR); // This is FF for Android, but we already have the OS to tell us that.
            res.description="Firefox "+ver;
            res.family=BrowserFamily.FIREFOX;
            res.renderingEngine+=" (Firefox"+ver+")"; // Firefox doesn't always mention the proper version of Gecko used
            if (ver.startsWith("2.") || ver.startsWith("3."))
                context.consume("ffco7", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume("pigfoot",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
        } else if ((ver = context.getcVersionAfterPattern("Netscape/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res.description="Netscape "+ver;
        } else if ((ver = context.getcVersionAfterPattern("Netscape6/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res.description="Netscape "+ver;
            context.consume("m18",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        } else if ((ver = context.getcVersionAfterPattern("Namoroka/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null ||
                   (ver = context.getcVersionAfterPattern("Shiretoko/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res.family=BrowserFamily.FIREFOX;
            res.description="Firefox "+ver;
        } else if ((ver = context.getcVersionAfterPattern("Minefield/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res.family=BrowserFamily.FIREFOX;
            res.description="Minefield " + ver + " (Firefox nightly build)";
            res.renderingEngine+=" (Minefield"+ver+")";
        } else if ((ver = context.getcVersionAfterPattern("SWB/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res.description="HP Secure Web Browser "+ver;
        } else if ((ver = context.getcVersionAfterPattern("BonEcho/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res.description="Firefox "+ver;
            res.family = BrowserFamily.FIREFOX;
        }


        context.consume("Gecko", MatchingType.EQUALS, MatchingRegion.REGULAR);
        context.consume("Mnenhy/",  MatchingType.BEGINS, MatchingRegion.REGULAR);
        context.consume("BonEcho/2",  MatchingType.BEGINS, MatchingRegion.REGULAR);
        return res;
    }

    static String getOperaVersion(UserAgentContext context, String fallback) {
        String v = getVersionVersion(context);
        if (v == null || v.length()==0) return fallback;
        return v;
    }

    static Browser tryOpera(UserAgentContext context) {
        String[]multi;
        String mono;
        Browser res = null;
        if ((mono = context.getcVersionAfterPattern("Opera Mini/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS, 2)) != null) {
            String v = getOperaVersion(context,"");
            if (v!=null && v.length()>0) {
                v = " (Opera " + v + ")";
            } else {
                v = "";
            }
            res = new Browser(Brand.OPERA, BrowserFamily.OPERA,"Opera Mini " + mono + v,getPrestoVersion(context, mono));
        } else if ((multi = context.getcNextTokens(new Matcher[] {new Matcher("Opera", MatchingType.EQUALS),
            new Matcher("^[0-9\\.]+$", MatchingType.REGEXP)
        },
        MatchingRegion.REGULAR)) != null) {
            res = new Browser(Brand.OPERA, BrowserFamily.OPERA,"Opera " + getOperaVersion(context,multi[1]),getPrestoVersion(context, multi[1]));
            if (context.consume("Bork-edition", MatchingType.EQUALS, MatchingRegion.REGULAR)) {
                res.description += " Bork edition";
            }
            context.consume("MSIE 6.0", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume("MSIE 5\\.[05]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        }
        return res;
    }

    static float tryParseVersionNumber(String s) {
        StringBuilder sb = new StringBuilder(20);
        int status = 0;
        for (int i=0 ; i<s.length() ; i++) {
            char c = s.charAt(i);
            if (status == 0) {
                if (Character.isDigit(c)) {
                    sb.append(c);
                } else if (c=='.') {
                    sb.append(c);
                    status=1;
                } else {
                    return Float.parseFloat(sb.toString());
                }
            } else {
                if (Character.isDigit(c)) {
                    sb.append(c);
                } else {
                    return Float.parseFloat(sb.toString());
                }
            }
        }
        return Float.parseFloat(sb.toString());
    }

    static Browser tryGetIE(UserAgentContext context, String possibleVersions, OS os) {

        Browser res=null;
        String verie,vertr,ver;
        if ((verie=context.getcVersionAfterPattern("MSIE ",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            float iever = tryParseVersionNumber(verie);

            if (iever < 6) {
                // Security patch MS01-058
                context.consume("T312461",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                context.consume("Q312461",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            }
            if (iever == 6) {
                // Security patch
                context.consume("Q312461",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            }

            if ((vertr=context.getcVersionAfterPattern("Trident/",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                float trver = tryParseVersionNumber(vertr);

                res = new Browser(Brand.MICROSOFT,BrowserFamily.IE,"IE " +iever,"Trident " + trver);

                if (trver == 4.0 && iever < 8) {
                    res.description = "IE 8 in compatibility mode " + res.description;
                    iever=8;
                } else if (trver == 5.0 && iever < 9) {
                    res.description = "IE 9 in compatibility mode " + res.description;
                } else if (trver == 6.0 && iever < 10) {
                    res.description = "IE 10 in compatibility mode " + res.description;
                }
            } else {
                res = new Browser(Brand.MICROSOFT,BrowserFamily.IE,"IE " +iever,"Trident for IE " + iever);
            }

            if (possibleVersions.indexOf(String.valueOf((int)Math.floor(iever))+",")==-1) res = null;

            if (res != null) {
                // Sometimes more than one of these is present... Dunno why.
                if (context.consume("Deepnet Explorer", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                    res.family = BrowserFamily.OTHER_TRIDENT;
                    res.description = "Deepnet Explorer";
                }
                if (context.consume("SlimBrowser", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                    res.family = BrowserFamily.OTHER_TRIDENT;
                    res.description = "SlimBrowser";
                }
                if (context.consume("Avant Browser", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                    res.family = BrowserFamily.OTHER_TRIDENT;
                    res.description = "Avant Browser";
                }
                if ((ver=context.getcVersionAfterPattern("Crazy Browser ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                    res.family = BrowserFamily.OTHER_TRIDENT;
                    res.description = "Crazy Browser " + ver;
                }
                if ((ver=context.getcVersionAfterPattern("America Online Browser ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                    res.family = BrowserFamily.OTHER_TRIDENT;
                    res.description = "AOL Browser " + ver;
                    context.consume("rev[0-9]\\.[0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
                }
                if (context.consume("MyIE2", MatchingType.EQUALS, MatchingRegion.PARENTHESIS) || context.consume("Maxthon", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                    res.family = BrowserFamily.OTHER_TRIDENT;
                    res.description = "Maxthon";
                }
                if ((ver=context.getcVersionAfterPattern("AOL ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                    res.description += " (using AOL " + ver + ")";
                    context.consume("Update a", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                } else if (context.consume("Update a", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                    res.description += " (using AOL)";
                }
                if ((ver=context.getcVersionAfterPattern("R1 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                    res.description += " (using RealOne "+ver+")";
                }
            }
            return res;
        }
        return null;

    }

    static Browser getBrowser(UserAgentContext context, OS os) {
        String userAgent = context.getUA();
        Browser res = null;
        int pos;
        String ver;
        String[]multi;

        boolean iStuff = os.family == OSFamily.IOS;

        // HTML to PDF converter of some sort
        if ((ver=context.getcVersionAfterPattern("EvoHtmlToPdf/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
            context.ignoreAllTokens();
            res = new Browser(Brand.UNKNOWN,BrowserFamily.ROBOT,"EvoHtmlToPdf "+ver,"Unknown");
        } else if ((ver=context.getcVersionAfterPattern("SMIT-Browser/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
            res = new Browser(Brand.UNKNOWN,BrowserFamily.OTHER,"SMIT Browser "+ver,"Unknown");
        } else if (context.getUA().startsWith("Windows Phone Search")) {
            context.getcNextTokens(new Matcher[] {new Matcher("Windows",MatchingType.EQUALS),new Matcher("Phone",MatchingType.EQUALS),new Matcher("Search",MatchingType.EQUALS)}
            , MatchingRegion.REGULAR);
            context.consume("[0-9]\\.[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
            context.consume("[0-9]{4}", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
            res = new Browser(Brand.MICROSOFT,BrowserFamily.OTHER,"Image Search Preview","");
        } else if ((ver=context.getcVersionAfterPattern("MSIEMobile ", MatchingType.BEGINS,MatchingRegion.PARENTHESIS))!=null) {
            res = new Browser(Brand.MICROSOFT,BrowserFamily.IE,"IE Mobile " +ver,getTridentVersion(context,"IE Mobile " +ver));
            context.consume("MSIE ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            context.consume("IEMobile ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            context.consume("Mozilla/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("compatible",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        } else if ((ver=context.getcVersionAfterPattern("IEMobile ", MatchingType.BEGINS,MatchingRegion.PARENTHESIS))!=null ||
                   (ver=context.getcVersionAfterPattern("IEMobile/", MatchingType.BEGINS,MatchingRegion.PARENTHESIS))!=null) {
            res = new Browser(Brand.MICROSOFT,BrowserFamily.IE,"IE Mobile " +ver,getTridentVersion(context,"IE Mobile " +ver));
            context.consume("MSIE ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            context.consume("Mozilla/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("compatible",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        } else if ((ver=context.getcVersionAfterPattern("S40OviBrowser/", MatchingType.BEGINS,MatchingRegion.REGULAR,3))!=null) {
            res = new Browser(Brand.NOKIA,BrowserFamily.OTHER,"OviBrowser " +ver,"OviBrowser " + ver);
            context.consume("Gecko/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("Mozilla/", MatchingType.BEGINS, MatchingRegion.REGULAR);
        } else if ((ver=context.getcVersionAfterPattern("NintendoBrowser/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
            res = new Browser(Brand.NINTENDO,BrowserFamily.OTHER_WEBKIT,"Nintendo Browser " +ver,"Nintendo Browser " + ver);
            context.consume("NX/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("Mozilla/5.0", MatchingType.EQUALS, MatchingRegion.REGULAR);
            context.consume("KHTML, like Gecko", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);


            if ((ver=context.getcVersionAfterPattern("AppleWebKit/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                res.renderingEngine = "AppleWebKit " + ver;
            }
        } else if (os.description.endsWith("Nintendo 3DS") && (ver=context.getcVersionAfterPattern("Version/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
            res = new Browser(Brand.NINTENDO,BrowserFamily.OTHER_WEBKIT,"Nintendo Browser 3DS " +ver,"Nintendo Browser 3DS " + ver);
            context.consume("Mozilla/5.0", MatchingType.EQUALS, MatchingRegion.REGULAR);
        } else if (context.contains("WebKit", MatchingType.CONTAINS, MatchingRegion.BOTH) ||
                   context.contains("Webkit", MatchingType.CONTAINS, MatchingRegion.BOTH) ||
                   (context.contains("com.google.GooglePlus/", MatchingType.BEGINS,MatchingRegion.REGULAR) && iStuff)) {
            if ((ver=context.getcVersionAfterPattern("NokiaBrowser/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.NOKIA,BrowserFamily.OTHER_WEBKIT,"NokiaBrowser " + ver,getWebkitVersion(context));
            } else if ((ver=context.getcVersionAfterPattern("Chromium/", MatchingType.BEGINS,MatchingRegion.REGULAR,2))!=null) {
                res = new Browser(Brand.CHROMIUM,BrowserFamily.CHROME,"Chromium "+ver, getWebkitVersion(context));
                context.consume("Chrome/", MatchingType.BEGINS,MatchingRegion.REGULAR);
            } else if (os.family == OSFamily.BADA && (ver = context.getcVersionAfterPattern("Dolfin/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.IBM,BrowserFamily.OTHER,"Dolfin " + ver,getWebkitVersion(context));
            } else if ((ver=context.getcVersionAfterPattern("Flock/", MatchingType.BEGINS,MatchingRegion.REGULAR,2))!=null) {
                res = new Browser(Brand.NOKIA,BrowserFamily.OTHER_WEBKIT,"Flock "+ver, getWebkitVersion(context));
                context.consume("Chrome/", MatchingType.BEGINS,MatchingRegion.REGULAR);
            } else if ((ver=context.getcVersionAfterPattern("YaBrowser/", MatchingType.BEGINS,MatchingRegion.REGULAR,2))!=null) {
                res = new Browser(Brand.UNKNOWN,BrowserFamily.OTHER_WEBKIT,"Yandex Browser "+ver, getWebkitVersion(context));
                context.consume("Chrome/", MatchingType.BEGINS,MatchingRegion.REGULAR);
            } else if ((ver=context.getcVersionAfterPattern("Chrome/", MatchingType.BEGINS,MatchingRegion.REGULAR,2))!=null) {
                res = new Browser(Brand.GOOGLE,BrowserFamily.CHROME,"Chrome "+ver, getWebkitVersion(context));
            } else if ((ver=context.getcVersionAfterPattern("Arora/", MatchingType.BEGINS,MatchingRegion.REGULAR,2))!=null) {
                res = new Browser(Brand.OTHER,BrowserFamily.OTHER_WEBKIT,"Arora "+ver, getWebkitVersion(context));
                context.consume("KHTML, like Gecko, Safari/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            } else if ((ver=context.getcVersionAfterPattern("Scourge/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.UNKNOWN,BrowserFamily.OTHER_WEBKIT,"Scourge "+ver, getWebkitVersion(context));
            } else if ((ver=context.getcVersionAfterPattern("Surf/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                context.consume("Compatible", MatchingType.EQUALS,MatchingRegion.REGULAR);
                context.consume("Safari", MatchingType.EQUALS,MatchingRegion.PARENTHESIS);
                res = new Browser(Brand.UNKNOWN,BrowserFamily.OTHER_WEBKIT,"Surf "+ver, getWebkitVersion(context));
            } else if ((ver=context.getcVersionAfterPattern("Silk/", MatchingType.BEGINS,MatchingRegion.BOTH,2))!=null) {
                res = new Browser(Brand.AMAZON,BrowserFamily.OTHER_WEBKIT,"Silk "+ver, getWebkitVersion(context));
            } else if ((ver=context.getcVersionAfterPattern("BrowserNG/", MatchingType.BEGINS,MatchingRegion.REGULAR,2))!=null) {
                res = new Browser(Brand.NOKIA,BrowserFamily.OTHER_WEBKIT,"BrowserNG "+ver, getWebkitVersion(context));
            } else if ((ver=context.getcVersionAfterPattern("Epiphany/", MatchingType.BEGINS,MatchingRegion.REGULAR,2))!=null) {
                res = new Browser(Brand.NOKIA,BrowserFamily.OTHER_WEBKIT,"Epiphany "+ver, getWebkitVersion(context));
            } else if (context.contains("Safari/", MatchingType.BEGINS, MatchingRegion.REGULAR) && !iStuff) {
                if (os.description.contains("Android")) {
                    String app = "";
                    if ((ver=context.getcVersionAfterPattern("BingWeb/", MatchingType.BEGINS,MatchingRegion.REGULAR,2))!=null)
                        app = " (with Bing app "+ver+")";
                    else if ((ver=context.getcVersionAfterPattern("GoogleGoggles-Android/", MatchingType.BEGINS,MatchingRegion.REGULAR,2))!=null)  {
                        context.consume("gzip", MatchingType.EQUALS, MatchingRegion.REGULAR);
                        app = " (with Google Goggles app "+ver+")";
                    }
                    else if ((ver=context.getcVersionAfterPattern("GSA/", MatchingType.BEGINS,MatchingRegion.REGULAR,2))!=null) {
                        app += " (with Google Search App)";
                    }
                    res = new Browser(Brand.GOOGLE,BrowserFamily.ANDROID,"Stock Browser" + app,getWebkitVersion(context));
                    context.consume("Version/", MatchingType.BEGINS,MatchingRegion.REGULAR);
                } else if (context.contains("BlackBerry/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                    res = new Browser(Brand.RIM,BrowserFamily.OTHER_WEBKIT,"Stock Browser",getWebkitVersion(context));
                } else if (os.family == OSFamily.WEBOS) {
                    context.consume("Version/", MatchingType.BEGINS,MatchingRegion.REGULAR);
                    if (os.vendor == Brand.HP)
                        context.consume("wOSBrowser/", MatchingType.BEGINS,MatchingRegion.REGULAR);
                    res = new Browser(os.vendor,BrowserFamily.OTHER_WEBKIT,"Stock Browser",getWebkitVersion(context));
                } else if (context.contains("Symbian", MatchingType.BEGINS, MatchingRegion.CONSUMED)) {
                    res = new Browser(Brand.NOKIA,BrowserFamily.OTHER_WEBKIT,"Stock Browser",getWebkitVersion(context));
                    context.consume("KHTML,like Gecko", MatchingType.EQUALS,MatchingRegion.PARENTHESIS);
                    context.consume("Mozilla/5.0", MatchingType.EQUALS,MatchingRegion.PARENTHESIS);
                } else if (context.contains("Version/", MatchingType.BEGINS, MatchingRegion.REGULAR) &&
                           (context.contains("Mac OS", MatchingType.CONTAINS, MatchingRegion.CONSUMED) ||
                            context.contains("Windows NT", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))) {
                    context.getcNextTokens(new Matcher[] {new Matcher("Public", MatchingType.EQUALS),
                                               new Matcher("Beta", MatchingType.EQUALS)
                    },
                    MatchingRegion.REGULAR);

                    res = new Browser(Brand.APPLE,BrowserFamily.SAFARI,"Safari " + getVersionVersion(context),getWebkitVersion(context));
                } else {
                    context.consume("Version/", MatchingType.BEGINS,MatchingRegion.REGULAR);
                    res = new Browser(Brand.UNKNOWN,BrowserFamily.OTHER_WEBKIT,"Safari-like",getWebkitVersion(context));
                }
            } else if (context.contains("AppleWebKit", MatchingType.BEGINS,MatchingRegion.REGULAR) ||
                       (context.contains("Safari/", MatchingType.BEGINS,MatchingRegion.REGULAR) && iStuff) ||
                       (context.contains("com.google.GooglePlus/", MatchingType.BEGINS,MatchingRegion.REGULAR) && iStuff)) {
                if (iStuff) {
                    String app = (context.contains("Safari/", MatchingType.BEGINS,MatchingRegion.REGULAR)) ? "" : " (in-app)";
                    if ((ver=context.getcVersionAfterPattern("CriOS/", MatchingType.BEGINS,MatchingRegion.REGULAR,2)) != null)
                        app = " (with Chrome Browser "+ver+")";
                    else if ((context.contains("[FBAN/FBForIPhone", MatchingType.BEGINS,MatchingRegion.REGULAR) ||
                              context.contains("[FBAN/FBIOS", MatchingType.BEGINS,MatchingRegion.REGULAR)) &&
                             (ver=context.getcVersionAfterPattern("FBAV/", MatchingType.CONTAINS,MatchingRegion.REGULAR)) != null) {
                        app = " (with Facebook app "+ver+")";

                        context.consume("AppleWebKit", MatchingType.EQUALS,MatchingRegion.REGULAR);
                        context.consume("OS;FBSV/", MatchingType.BEGINS,MatchingRegion.REGULAR);
                        context.consume("FBCR/.*;FBID/.*;FBLC/.*", MatchingType.REGEXP,MatchingRegion.REGULAR);
                        context.consume("touch;FBSN/iPhone", MatchingType.EQUALS,MatchingRegion.REGULAR);

                    } else if (null != context.getcNextTokens(new Matcher[] {new Matcher("Twitter", MatchingType.EQUALS),
                        new Matcher("for", MatchingType.EQUALS),
                        new Matcher("iPhone", MatchingType.EQUALS)
                    },
                    MatchingRegion.REGULAR)) {
                        app = " (with Twitter app)";
                    }
                    else if ((ver=context.getcVersionAfterPattern("GSA/", MatchingType.BEGINS,MatchingRegion.REGULAR)) != null) {
                        app = " (with Google app)";
                    } else if ((ver=context.getcVersionAfterPattern("com.google.GooglePlus/", MatchingType.BEGINS,MatchingRegion.REGULAR)) != null) {
                        app = " (with Google Plus app)";
                    } else if ((ver=context.getcVersionAfterPattern("BingWeb/", MatchingType.BEGINS,MatchingRegion.REGULAR,2))!=null) {
                        app = " (with Bing app "+ver+")";
                    } else if ((ver=context.getcVersionAfterPattern("iLunascape/", MatchingType.BEGINS,MatchingRegion.REGULAR,2))!=null) {
                        app = " (with iLunascape Browser "+ver+")";
                    } else if ((ver=context.getcVersionAfterPattern("Mercury/", MatchingType.BEGINS,MatchingRegion.REGULAR,2))!=null) {
                        app = " (with Mercury Browser "+ver+")";
                    } else if ((ver=context.getcVersionAfterPattern("Mercury/", MatchingType.BEGINS,MatchingRegion.REGULAR,2))!=null) {
                        app = " (with Mercury Browser "+ver+")";
                    } else if (context.consume("DiigoBrowser", MatchingType.BEGINS,MatchingRegion.REGULAR)) {
                        app = " (with Diigo browser)";
                    }

                    if (app.length()>0) {

                    }
                    res = new Browser(Brand.APPLE,BrowserFamily.IOS,"Stock Browser"+app,getWebkitVersion(context));

                    context.consume("Mobile/", MatchingType.BEGINS,MatchingRegion.REGULAR);
                } else {
                    res = new Browser(Brand.UNKNOWN,BrowserFamily.OTHER_WEBKIT,"WebKit-based",getWebkitVersion(context));
                }
            }
            context.consume("Version/", MatchingType.BEGINS,MatchingRegion.REGULAR);
        } else if ((ver=context.getcVersionAfterPattern("Konqueror/", MatchingType.BEGINS,MatchingRegion.PARENTHESIS))!=null) {
            consumeMozilla(context);
            context.consume("like Gecko", MatchingType.EQUALS,MatchingRegion.PARENTHESIS);
            context.consume("20[01][0-9][01][0-9][0-3][0-9]", MatchingType.REGEXP,MatchingRegion.PARENTHESIS);
            res = new Browser(Brand.KDE,BrowserFamily.KHTML,"Konqueror "+ver,getKHTMLVersion(context));
        } else if ((ver=context.getcVersionAfterPattern("Polaris/", MatchingType.BEGINS,MatchingRegion.PARENTHESIS))!=null) {
            res = new Browser(Brand.INFRAWARE,BrowserFamily.OTHER,"Polaris "+ver,"");
        } else if (context.contains("KHTML, like Gecko", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) ||
                   context.contains("KHTML/", MatchingType.BEGINS, MatchingRegion.REGULAR)) {
            consumeMozilla(context);
            context.consume("like Gecko", MatchingType.EQUALS,MatchingRegion.PARENTHESIS);
            res = new Browser(Brand.KDE,BrowserFamily.KHTML,"KHTML-based",getKHTMLVersion(context));
        } else if ((ver=context.getcVersionAfterPattern("NetFront/", MatchingType.BEGINS,MatchingRegion.BOTH))!=null ||
                   (ver=context.getcVersionAfterPattern("Browser/NetFront/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {

            String ver2;
            if ((ver2=context.getcVersionAfterPattern("Novarra-Vision/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.NOVARRA,BrowserFamily.OTHER,"Vision","Vision "+ver2);
            } else {
                res = new Browser(Brand.ACCESSCO,BrowserFamily.NETFRONT,"NetFront","NetFront "+ver);
            }

            context.consume("NetFront/", MatchingType.BEGINS, MatchingRegion.BOTH);
        } else if (context.contains("Mozilla/3.0", MatchingType.EQUALS, MatchingRegion.REGULAR) &&
                   context.consume("Sun", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res = new Browser(Brand.SUN,BrowserFamily.OTHER,"HotJava","Java");
            context.consume("Mozilla/3.0", MatchingType.EQUALS, MatchingRegion.REGULAR);
        } else if ((ver=context.getcVersionAfterPattern("Lynx/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
            res = new Browser(Brand.UNKNOWN,BrowserFamily.TEXTBASED,"Lynx " + ver,"Text-based - Lynx");

            context.consume("libwww-FM/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("SSL-MM/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("OpenSSL/", MatchingType.BEGINS, MatchingRegion.REGULAR);

        } else if (context.consume("ELinks", MatchingType.EQUALS,MatchingRegion.REGULAR)) {
            ver = context.getcToken("[0-9]+\\.[0-9\\.a-zA-Z-]+", MatchingType.REGEXP,MatchingRegion.PARENTHESIS);
            if (ver == null) ver = "";
            res = new Browser(Brand.UNKNOWN,BrowserFamily.TEXTBASED,("ELinks " + ver).trim(),"Text-based - ELinks");
        } else if ((ver = context.getcVersionAfterPattern("ELinks/", MatchingType.BEGINS,MatchingRegion.REGULAR)) != null ||
                   ((ver = context.getcVersionAfterPattern("ELinks/", MatchingType.BEGINS,MatchingRegion.PARENTHESIS)) != null && context.consume("Mozilla/5.0", MatchingType.EQUALS,MatchingRegion.REGULAR))) {
            res = new Browser(Brand.UNKNOWN,BrowserFamily.TEXTBASED,("ELinks " + ver).trim(),"Text-based - ELinks");
            context.consume("textmode", MatchingType.EQUALS,MatchingRegion.PARENTHESIS);
            context.consume("[0-9]+x[0-9]+(-[0-9])?", MatchingType.REGEXP,MatchingRegion.PARENTHESIS);
        } else if (context.consume("Links", MatchingType.EQUALS,MatchingRegion.REGULAR)) {
            ver = context.getcToken("[0-9]+\\.[0-9\\.a-zA-Z-]+", MatchingType.REGEXP,MatchingRegion.PARENTHESIS);
            if (ver == null) ver = "";
            res = new Browser(Brand.UNKNOWN,BrowserFamily.TEXTBASED,("Links " + ver).trim(),"Text-based - Links");
        } else if ((ver=context.getcVersionAfterPattern("w3m/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
            res = new Browser(Brand.UNKNOWN,BrowserFamily.TEXTBASED,"w3m " + ver,"Text-based w3m");
            context.consume("Lynx compatible", MatchingType.EQUALS,MatchingRegion.PARENTHESIS);
        } else if (context.contains("Mozilla/4.61", MatchingType.EQUALS, MatchingRegion.REGULAR) &&
                   context.consume("BrowseX", MatchingType.EQUALS, MatchingRegion.REGULAR)) {
            context.consume("Mozilla/4.61", MatchingType.EQUALS, MatchingRegion.REGULAR);
            context.consume("-", MatchingType.EQUALS, MatchingRegion.REGULAR);
            pos = context.getUA().indexOf("BrowseX (");
            ver = getVersionNumber(context.getUA(), pos+9);
            res = new Browser(Brand.UNKNOWN,BrowserFamily.OTHER,"BrowseX " + ver,"BrowseX " + ver);
            context.consume(ver, MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
        } else if ((ver = context.getcVersionAfterPattern("Gecko/", MatchingType.BEGINS, MatchingRegion.REGULAR))!=null ||
                   context.contains("Galeon/",  MatchingType.BEGINS, MatchingRegion.REGULAR) ||
                   context.contains("GranParadiso/",  MatchingType.BEGINS, MatchingRegion.REGULAR) ||
                   (ver = context.getcVersionAfterPattern("Mozilla/5.0/Gecko/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res = getGecko(context, ver, os);
            context.consume("Mozilla/", MatchingType.BEGINS, MatchingRegion.REGULAR);
        } else if (context.contains("Gecko", MatchingType.BEGINS, MatchingRegion.BOTH)) {
            res = getGecko(context,"", os);
        } else if ((ver = context.getcVersionAfterPattern("UP.Browser/", MatchingType.BEGINS, MatchingRegion.REGULAR, 3)) != null) {
            res = new Browser(Brand.OPENWAVE,BrowserFamily.OTHER,"Mobile Browser " + ver, "Mobile Browser " + ver);
            context.consume("MMP/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("GUI", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        } else if (context.consume("Opera Mobi", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
            multi = context.getcNextTokens(new Matcher[] {
                                               new Matcher("Opera", MatchingType.EQUALS),
                                               new Matcher("[0-9\\.]+", MatchingType.REGEXP)
                                           }, MatchingRegion.REGULAR);
            String version = multi == null ? "" : (" "+multi[1]);
            if (version.length()==0) {
                version = getVersionVersion(context);
                if (version!=null && version.length()>0) version = " " + version;
            }
            String b = "Mobi" + version;
            res = new Browser(Brand.OPERA,BrowserFamily.OPERA,"Opera " + b, getPrestoVersion(context, b));
            context.consume("Opera/9.80",  MatchingType.EQUALS, MatchingRegion.REGULAR);
        } else if ((ver = context.getcVersionAfterPattern("NetPositive/",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            consumeMozilla(context);
            res = new Browser(Brand.BE,BrowserFamily.OTHER,"NetPositive " + ver,"");
        } else if ((ver = context.getcVersionAfterPattern("Acorn-HTTP/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res = new Browser(Brand.ACORN,BrowserFamily.OTHER,"Acorn HTTP " + ver,"");
            consumeMozilla(context);
            context.consume("Compatible", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        } else if ((ver = context.getcVersionAfterPattern("Oregano ",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            res = new Browser(Brand.OREGAN,BrowserFamily.OTHER,"Oregano " + ver,"");
            consumeMozilla(context);
            context.consume("Compatible", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        } else if (os.vendor == Brand.NINTENDO && context.getUA().startsWith("Opera/9.50") && context.getUA().contains("DSi") &&
                   (ver = context.getcVersionAfterPattern("Opera/",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            res = new Browser(Brand.OPERA,BrowserFamily.OPERA,"For DSi, ver " + ver,"Presto 2.1"); // See http://en.wikipedia.org/wiki/Nintendo_DS_%26_DSi_Browser
            context.consume("Opera/9.50", MatchingType.EQUALS, MatchingRegion.REGULAR);
        } else




            // -----------------------------
            if (context.contains("Mozilla/4\\.[01]", MatchingType.REGEXP, MatchingRegion.REGULAR) &&
                    context.contains("compatible",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {

                res = tryOpera(context);
                if (res == null) {
                    if ((ver = context.getcVersionAfterPattern("Lotus-Notes/",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                        res = new Browser(Brand.IBM,BrowserFamily.OTHER,"Lotus Notes " + ver,"Lotus Notes "+ver);
                    } else if (os.vendor == Brand.PALM && (ver = context.getcVersionAfterPattern("Blazer/",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                        res = new Browser(Brand.HANDSPRING,BrowserFamily.OTHER,"Blazer " + ver,"Blazer "+ver);
                        context.consume("MSIE 6.0",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                    }
                }
                if (res == null) res = tryGetIE(context,"4,5,6,7,8,", os);
                if (res == null) {
                    if ((ver = context.getcVersionAfterPattern("AvantGo ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                        res = new Browser(Brand.OTHER,BrowserFamily.ROBOT,"AvantGo " + ver,"");
                    }
                }
                if (res != null) {
                    context.consume("Mozilla/4.0", MatchingType.EQUALS, MatchingRegion.REGULAR);
                    context.consume("compatible",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                }

                // -----------------------------
            } else if (context.contains("Mozilla/2.0", MatchingType.EQUALS, MatchingRegion.REGULAR) &&
                       context.contains("compatible",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                if (res == null) res = tryGetIE(context,"3,", os);
                if (res != null) {
                    context.consume("Mozilla/2.0", MatchingType.EQUALS, MatchingRegion.REGULAR);
                    context.consume("compatible",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                }

                // -----------------------------
            } else if (context.contains("Mozilla/5.0", MatchingType.EQUALS, MatchingRegion.REGULAR)) {

                res = tryOpera(context);

                if (res == null  &&
                        context.contains("compatible",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                    res = tryGetIE(context,"9,10,", os);
                    if (res != null) {
                        context.consume("compatible",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                    }
                }
                if (res == null) {
                    if ((ver = context.getcVersionAfterPattern("AvantGo ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                        res = new Browser(Brand.OTHER,BrowserFamily.ROBOT,"AvantGo " + ver,"");
                    }
                }
                if (res != null) {
                    context.consume("Mozilla/5.0", MatchingType.EQUALS, MatchingRegion.REGULAR);
                }

                // -----------------------------
            } else if (context.contains("Mozilla/1.22", MatchingType.EQUALS, MatchingRegion.REGULAR) &&
                       context.contains("compatible",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {

                res = tryGetIE(context,"2,", os);

                if (res != null) {
                    context.consume("Mozilla/1.22", MatchingType.EQUALS, MatchingRegion.REGULAR);
                    context.consume("compatible",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                }

                // -----------------------------
            } else if (context.getUA().startsWith("Opera/") && (ver = context.getcVersionAfterPattern("Opera/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
                res = tryOpera(context);
                if (res == null) {
                    String ver2 = getVersionVersion(context);
                    if (ver2 != null && ver2.length()>0) ver = ver2;
                    res = new Browser(Brand.OPERA,BrowserFamily.OPERA,"Opera " + ver,getPrestoVersion(context, ver));
                }
            } else if ((ver = context.getcVersionAfterPattern("Java/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.SUN,BrowserFamily.ROBOT,"Java " + ver,"n/a");
                context.consume("Mozilla/",MatchingType.BEGINS,MatchingRegion.REGULAR);
            } else if ((ver = context.getcVersionAfterPattern("java ",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                res = new Browser(Brand.SUN,BrowserFamily.ROBOT,"Java " + ver,"n/a");
            } else if ((ver = context.getcVersionAfterPattern("LinkScan/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.ELSOP,BrowserFamily.ROBOT,"LinkScan " + ver,"n/a");
            } else if ((ver = context.getcVersionAfterPattern("amaya/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.OTHER,BrowserFamily.OTHER,"amaya " + ver,"");
                context.consume("libwww/",  MatchingType.BEGINS, MatchingRegion.REGULAR);
            } else if ((ver = context.getcVersionAfterPattern("Dillo/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.OTHER,BrowserFamily.OTHER,"Dillo " + ver,"");
            }



        if (res == null) {

            // We will interpret Mozilla/4.x as Netscape Communicator is and only if x is not 0 or 5
            // Don't ask why.
            if (userAgent.startsWith("Mozilla/4.") &&
                    !userAgent.startsWith("Mozilla/4.0 ") &&
                    !userAgent.startsWith("Mozilla/4.5 ")) {
                if (context.consume("OffByOne",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                    res = new Browser(Brand.OTHER,BrowserFamily.OTHER,"Off By One","");
                    context.consume("Mozilla/4.",  MatchingType.BEGINS, MatchingRegion.REGULAR);
                    // That's a browser by Home Page Software Inc.
                } else {
                    res = new Browser(Brand.NETSCAPE,BrowserFamily.OTHER,"Communicator","Communicator " + context.getcVersionAfterPattern("Mozilla/", MatchingType.BEGINS, MatchingRegion.REGULAR));
                    context.consume("I",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                    context.consume("Nav",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                }
                context.consume("compatible",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            } else
                return new Browser(Brand.UNKNOWN,BrowserFamily.UNKNOWN,"","");
        }
        return res;
    }

    static Device getDevice(UserAgentContext context, Browser b, OS o) {
        String ua = context.getUA();
        String arm = "ARM";

        int pos;
        String ver;
        // Bots & SDKs
        if (o.family == OSFamily.ANDROID &&
                (context.consume("sdk ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) ||
                 context.consume("Android SDK ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) ||
                 context.consume("google_sdk ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)))
            return new Device("",DeviceType.SDK,Brand.GOOGLE,"Android sdk");
        if (context.consume("iPhone Simulator", MatchingType.EQUALS, MatchingRegion.PARENTHESIS))
            return new Device("",DeviceType.SDK,Brand.APPLE,"iPhone Simulator");
        if (context.consume("Google Web Preview", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            if (o.family == OSFamily.ANDROID)
                context.consume("generic", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            if (o.family == OSFamily.IOS)
                context.consume("iPhone", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            return new Device("",DeviceType.BOT,Brand.GOOGLE,"Web Preview");
        }
        if (context.consume("yacybot", MatchingType.EQUALS, MatchingRegion.REGULAR)) {
            context.consumeAllTokens();
            return new Device("",DeviceType.BOT,Brand.YACI,"YaCy Bot");
        }
        if (context.contains("EvoHtmlToPdf/", MatchingType.BEGINS,MatchingRegion.CONSUMED)) return new Device("",DeviceType.BOT,Brand.UNKNOWN,"EvoHtmlToPdf");
        if ((ver=context.getcVersionAfterPattern("del.icio.us-thumbnails/", MatchingType.BEGINS,MatchingRegion.BOTH))!=null)
            return new Device("",DeviceType.BOT,Brand.DELICIOUS,"Thumbnails crawler " + ver);


        // Nokia stuff
        //if (context.getcToken("Nokia7650/", MatchingType.BEGINS, MatchingRegion.BOTH) != null) return new Device("",DeviceType.BOT,Brand.UNKNOWN,"COUCOUCOUCOU");
        if (o.vendor == Brand.NOKIA) {
            Device res = new Device(arm,DeviceType.PHONE,Brand.NOKIA,"");
            if (context.getcToken("NokiaN95", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.device = "N95";
            if (context.getcToken("NokiaN9", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.device = "N9";
            if (o.description.equals("Series40") || o.description.equals("Symbian OS")) {
                if (context.getcToken("Nokia311", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.device = "Asha 311";
                if (context.getcToken("NokiaX3-02", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.device = "X3 Touch and Type";
                if (context.getcToken("Nokia305", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.device = "Asha 305";
                if (context.getcToken("NokiaC3-00", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.device = "C3-00";
                if (context.getcToken("NokiaC7-00", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.device = "C7-00";
                if (context.getcToken("Nokia202", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.device = "Asha 202";
                if (context.getcToken("Nokia 3650", MatchingType.EQUALS, MatchingRegion.PARENTHESIS) != null) res.device = "3650";
                if (context.getcToken("Nokia6300", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.device = "6300";
                if (context.getcToken("Nokia7650/", MatchingType.BEGINS, MatchingRegion.REGULAR) != null) res.device = "7650";
                if (context.getcToken("NokiaX2-02", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.device = "X2-02";
                if (context.getcToken("NokiaX6-00", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.device = "X6-00";
                if (context.getcToken("NokiaN73", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.device = "N73";
                if (context.getcToken("NokiaN8-", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.device = "N8";
                if (context.getcToken("NokiaN81-", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.device = "N81";
                if (context.getcToken("NokiaE5-", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.device = "E5";
                if (context.getcToken("NokiaE51-", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.device = "E51";
                if (context.getcToken("NokiaE63-", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.device = "E63";
                if (context.getcToken("NokiaE71-", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.device = "E71";
                if (context.getcToken("NokiaE60", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.device = "E60";
                if (context.getcToken("NokiaE90", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.device = "E90";
                if (context.getcToken("NokiaN85-", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.device = "N85";
                if (context.getcToken("NokiaN86-", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.device = "N86";
                if (context.getcToken("NokiaN72/", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.device = "N72";
                if (context.getcToken("NokiaN93-", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.device = "N93";

                if (context.getcToken("Nokia808PureView/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.device = "808 PureView";
                if (context.getcToken("Nokia5233/", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.device = "5233";
                if (context.getcToken("Nokia5230/", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.device = "5230";
                if (context.getcToken("Nokia500/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.device = "500";
                if (context.getcToken("Nokia701", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.device = "701";
                if (context.getcToken("Nokia3230", MatchingType.BEGINS, MatchingRegion.REGULAR) != null) res.device = "3230";
                if (context.getcToken("es50", MatchingType.EQUALS, MatchingRegion.REGULAR) != null) res.device = "ES50";
                if (context.getcToken("es61", MatchingType.EQUALS, MatchingRegion.REGULAR) != null) res.device = "ES61";
                if (context.getcToken("es61i", MatchingType.EQUALS, MatchingRegion.REGULAR) != null) res.device = "ES61";
                if (context.getcToken("Nokia[ ]?6630/.*", MatchingType.REGEXP, MatchingRegion.BOTH) != null) res.device = "6630";
                if (context.getcToken("Nokia5530c-2/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.device = "5530 XpressMusic";
                if (context.getcToken("Nokia5800d", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.device = "5800 XpressMusic";
            }
            if (context.consume("NokiaN-GageQD", MatchingType.BEGINS, MatchingRegion.REGULAR)) {
                context.consume("SymbianOS/", MatchingType.BEGINS, MatchingRegion.REGULAR);
                context.consume("[0-9]\\.[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
                res.device = "N-Gage";
                res.deviceType = DeviceType.CONSOLE;
            }
            if (res.device.length()>0) return res;

            if (context.getUA().startsWith("SonyEricsson")) {
                res = new Device(arm,DeviceType.PHONE,Brand.SONY,"");
                if (context.consume("SonyEricssonU5", MatchingType.BEGINS, MatchingRegion.REGULAR)) res.device = "Vivaz";
                if (context.consume("SonyEricssonU1[ai]/.*", MatchingType.REGEXP, MatchingRegion.REGULAR)) res.device = "Satio";
                if (res.device.length()==0) {
                    ver = context.getcVersionAfterPattern("SonyEricsson", MatchingType.BEGINS, MatchingRegion.REGULAR);
                    res = new Device(arm,DeviceType.PHONE,Brand.SONY,ver);
                }
                return res;
            }
        }

        if (o.family == OSFamily.WEBOS) {
            if (o.vendor == Brand.PALM) {
                if ((ver = context.getcVersionAfterPattern("Pixi/", MatchingType.BEGINS, MatchingRegion.REGULAR)) != null)
                    return new Device(arm,DeviceType.PHONE,Brand.PALM,"Pixi " + ver);
                if ((ver = context.getcVersionAfterPattern("Pre/", MatchingType.BEGINS, MatchingRegion.REGULAR)) != null)
                    return new Device(arm,DeviceType.PHONE,Brand.PALM,"Pre " + ver);
                if ((ver = context.getcVersionAfterPattern("P160UNA/", MatchingType.BEGINS, MatchingRegion.REGULAR)) != null)
                    return new Device(arm,DeviceType.PHONE,Brand.HP,"Veer 4G " + ver);
            }
            if (o.vendor == Brand.HP) {
                if ((ver = context.getcVersionAfterPattern("TouchPad/", MatchingType.BEGINS, MatchingRegion.REGULAR)) != null)  {
                    context.consume("hp-tablet", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                    return new Device(arm,DeviceType.TABLET,Brand.HP,"TouchPad " + ver);
                }
            }
        } else if (o.vendor == Brand.PALM) {
            context.consume("16;[0-9]+x[0-9]+", MatchingType.REGEXP, MatchingRegion.REGULAR);
            if (context.consume("PalmSource/Palm-D053", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                context.consume("Palm680", MatchingType.BEGINS, MatchingRegion.REGULAR);
                return new Device(arm,DeviceType.PHONE,Brand.PALM,"Treo 680");
            }
            if (context.consume("/Palm 500v/" , MatchingType.BEGINS, MatchingRegion.REGULAR)) return new Device(arm,DeviceType.PHONE,Brand.PALM,"Treo 500v");
            if (context.consume("PalmSource/Palm-D052" , MatchingType.BEGINS, MatchingRegion.PARENTHESIS )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"Treo 700p");
            if (context.consume("Palm750/v0100" , MatchingType.BEGINS, MatchingRegion.REGULAR )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"750");
            if (context.consume("Palm750/v0000" , MatchingType.BEGINS, MatchingRegion.REGULAR )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"Treo 750w");
            if (context.consume("PalmSource/Palm-D060" , MatchingType.BEGINS, MatchingRegion.PARENTHESIS )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"Treo 755p");
            if (context.consume("Treo800w/v0100" , MatchingType.BEGINS, MatchingRegion.REGULAR )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"Treo 800w");
            if (context.consume("Treo850/v0100" , MatchingType.BEGINS, MatchingRegion.REGULAR )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"Treo850");
            if (context.consume("Alltel_Treo850e" , MatchingType.BEGINS, MatchingRegion.REGULAR )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"Treo850e");
            if (context.consume("PalmSource/Palm-TnT5" , MatchingType.BEGINS, MatchingRegion.PARENTHESIS  )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"Treo 600");
            if (context.consume("PalmSource/Palm-TunX" , MatchingType.BEGINS, MatchingRegion.PARENTHESIS  )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"Tunx");
            if (context.consume("PalmSource/hspr-H102" , MatchingType.BEGINS, MatchingRegion.PARENTHESIS  )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"Treo 650");
            if (context.consume("PalmSource/Palm-D050" , MatchingType.BEGINS, MatchingRegion.PARENTHESIS  )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"TX");
            if (context.consume("PalmSource/Palm-D062" , MatchingType.BEGINS, MatchingRegion.PARENTHESIS  )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"Centro");
            if (context.consume("PalmSource/" , MatchingType.BEGINS, MatchingRegion.PARENTHESIS  )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"");
        }
        // Android devices
        if (o.family == OSFamily.ANDROID) {
            context.consume("Dalvik/", MatchingType.BEGINS, MatchingRegion.REGULAR);

            // Samsung

            if (context.contains("SAMSUNG-SGH-", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) ||
                    context.contains("SGH-", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                Device device = null;
                if (context.consume("(SAMSUNG-)?SGH-T999.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3");
                else if (context.consume("(SAMSUNG-)?SGH-T989.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S2");
                else if (context.consume("(SAMSUNG-)?SGH-T959.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S");
                else if (context.consume("(SAMSUNG-)?SGH-T889.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note 2");
                else if (context.consume("(SAMSUNG-)?SGH-T769.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S Blaze 4G");
                else if (context.consume("(SAMSUNG-)?SGH-T759.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Exhibit 4G");
                else if (context.consume("(SAMSUNG-)?SGH-I896.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S");
                else if (context.consume("(SAMSUNG-)?SGH-I747.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3");
                else if (context.consume("(SAMSUNG-)?SGH-I407.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Amp");
                else if (context.consume("(SAMSUNG-)?SGH-I897.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Captivate");
                else if (context.consume("(SAMSUNG-)?SGH-I777.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S2");
                else if (context.consume("(SAMSUNG-)?SGH-I727.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S2");
                else if (context.consume("(SAMSUNG-)?SGH-I717.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note");
                else if (context.consume("(SAMSUNG-)?SGH-I317.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note 2");
                else if (context.consume("(SAMSUNG-)?SGH-T679.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Exhibit II 4G");
                else if (context.consume("(SAMSUNG-)?SGH-I997.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Infuse 4G");
                else if (context.consume("(SAMSUNG )?SGH-T849.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 7.0");
                else if (context.consume("(SAMSUNG )?SGH-T859.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 10.1");
                else if (context.consume("(SAMSUNG )?SGH-T499.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Dart");
                else if (context.consume("(SAMSUNG )?SGH-T589.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Gravity Smart");
                else if (context.consume("(SAMSUNG )?SGH-T839.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Sidekick 4G");

                if (device != null) {
                    if (context.contains("(SAMSUNG[- ])SGH-..../.*", MatchingType.REGEXP, MatchingRegion.CONSUMED)) {
                        context.consume("Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
                    }
                    return device;
                }

                return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Unknown");
            }

            if (context.contains("SAMSUNG GT-", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) ||
                    context.contains("GT-", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                context.consume("Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
                if (context.consume("(SAMSUNG )?GT-I9100.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S2");
                if (context.consume("(SAMSUNG )?GT-S6102.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Y Duos");
                if (context.consume("(SAMSUNG )?GT-S5839i.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Ace");
                if (context.consume("(SAMSUNG )?GT-S5830.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Ace");
                if (context.consume("(SAMSUNG )?GT-S5690.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Xcover");
                if (context.consume("(SAMSUNG )?GT-S5670.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Fit");
                if (context.consume("(SAMSUNG )?GT-S5660.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Gio");
                if (context.consume("(SAMSUNG )?GT-S536[0-3].*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Y");
                if (context.consume("(SAMSUNG )?GT-S5570.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Mini");

                if (context.consume("(SAMSUNG )?GT-P75[01]0.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 10.1");
                if (context.consume("(SAMSUNG )?GT-P68[01]0.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 7.7");
                if (context.consume("(SAMSUNG )?GT-P73[01]0.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 8.9");
                if (context.consume("(SAMSUNG )?GT-P6200.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 7 Plus");
                if (context.consume("(SAMSUNG )?GT-P51[01]0.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 2 10.1");
                if (context.consume("(SAMSUNG )?GT-P5113.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 2 10.1");
                if (context.consume("(SAMSUNG )?GT-P3113.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 2 7");
                if (context.consume("(SAMSUNG )?GT-P31[01]0.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 2 7");
                if (context.consume("(SAMSUNG )?GT-P10[01]0.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab");
                if (context.consume("(SAMSUNG )?GT-P6210.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab");

                if (context.consume("(SAMSUNG )?GT-N80[01]0.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Note 10.1");
                if (context.consume("(SAMSUNG )?GT-N8005.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Note 10.1");
                if (context.consume("(SAMSUNG )?GT-N8013.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note");
                if (context.consume("(SAMSUNG )?GT-N7105.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note 2");
                if (context.consume("(SAMSUNG )?GT-N7100.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note 2");
                if (context.consume("(SAMSUNG )?GT-N7100.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note 2");
                if (context.consume("(SAMSUNG )?GT-N7000.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note");
                //TODO: UNTESTED
                if (context.consume("(SAMSUNG )?GT-5100.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Note 8.0");

                if (context.consume("(SAMSUNG )?GT-I5510.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy 551");
                if (context.consume("(SAMSUNG )?GT-I8190.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3 Mini");
                if (context.consume("(SAMSUNG )?GT-I5500.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy 5");
                if (context.consume("(SAMSUNG )?GT-I9001.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S Plus");
                if (context.consume("(SAMSUNG )?GT-I5700.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Spica");
                if (context.consume("(SAMSUNG )?GT-I9305T.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3");
                if (context.consume("(SAMSUNG )?GT-I9305.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3");
                if (context.consume("(SAMSUNG )?GT-I9300.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3");
                if (context.consume("(SAMSUNG )?GT-I9220.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note");
                if (context.consume("(SAMSUNG )?GT-I9000.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S");
                if (context.consume("(SAMSUNG )?GT-I9003.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy SL");
                if (context.consume("(SAMSUNG )?GT-I8160.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Ace 2");
                if (context.consume("(SAMSUNG )?GT-I5800.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy 3");
                if (context.consume("(SAMSUNG )?GT-I5801.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Apollo");
                if (context.consume("(SAMSUNG )?GT-I8150.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy W");


                if (context.consume("(SAMSUNG )?GT-B5510.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Y Pro");
                if (context.consume("(SAMSUNG )?GT-B7510.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Pro");

                return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Unknown");
            }


            if (context.consume("Galaxy S II", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S2");
            if (context.consume("Galaxy Build", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy");
            if (context.consume("SCH-R950", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note 2");
            if (context.consume("SCH-R530U", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3");
            if (context.consume("SCH-I939", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3");
            if (context.consume("SCH-I605", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note 2");
            if (context.consume("SCH-I535", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3");
            if (context.consume("SCH-I500", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S");
            if (context.consume("SC-06D", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3");
            if (context.consume("SPH-M820", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Prevail");
            if (context.consume("SPH-L900", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note 2");
            if (context.consume("SPH-L710", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3");
            if (context.consume("SPH-D710", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S2");
            if (context.consume("SPH-M920", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Transform");
            if (context.consume("SPH-M900", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Moment");
            if (context.consume("SPH-D700", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Epic 4G");
            if (context.consume("SPH-M910", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Intercept");
            if (context.consume("SPH-M930", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Transform Ultra");
            if (context.consume("SPH-P100", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 7");
            if (context.consume("SPH-D600", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Conquer 4G");

            if (context.consume("SHW-M380K", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 10.1");
            if (context.consume("SHW-M250K", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S2");
            if (context.consume("SHW-M110S", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S");
            if (context.consume("SHV-E210S", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3");
            if (context.consume("SHV-E210L", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3");
            if (context.consume("SHV-E210K", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3");
            if (context.consume("SHV-E160S", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note");


            // KTTECH
            if (context.consume("KM-E100", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.KTTECH,"KM-E100");

            // ZTE
            if (context.consume("ZTE-N880E", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.ZTE,"N880E");
            if (context.consume("ZTE U970_TD/1.0", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.ZTE,"Grand X");
            if (context.consume("ZTE N880E", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.ZTE,"N880E");
            if (context.consume("ZTE Z992", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.ZTE,"Z992");
            if (context.consume("Z995", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.ZTE,"Z995");
            if (context.consume("Orange Tactile internet 2", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.ZTE,"Blade");
            if (context.consume("ZTE V768", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.ZTE,"Concord (V768)");
            if (context.consume("ZTE-RACER", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.ZTE,"Racer");

            // Huawei
            if (context.consume("U8350", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Boulder U8350");
            if (context.consume("Huawei U8800", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Ideos X5");
            if (context.consume("U8180", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Boulder Ideos X1");
            if (context.consume("HUAWEI-M835", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Ideos");
            if (context.consume("HUAWEI-M860", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Ascend");
            if (context.consume("H866C", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Ascend Y");
            if (context.consume("HUAWEI_T8620_", MatchingType.BEGINS, MatchingRegion.REGULAR)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Ascend Y200T (T8620)");
            if (context.consume("T-Mobile myTouch Build/HuaweiU8680", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"myTouch (8680)");
            if (context.consume("Prism Build/HuaweiU8651", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Prism (8651)");
            if (context.consume("U8815", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Ascend G300 (U8815)");
            if (context.consume("HUAWEI U8950", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Ascend G600 (U8950)");
            if (context.consume("Huawei-U8665", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Fusion 2");
            if (context.consume("Huawei-U8652", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Fusion U8652");
            if (context.consume("TURKCELL MaxiPRO5", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Honor U8860");

            // SONY
            if (context.consume("SonyST21i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia");
            if (context.consume("(SonyEricsson)?U20i.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia X10 mini pro");
            if (context.consume("SonyLT30p", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia T");
            if (context.consume("Sony Tablet S", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SONY,"Tablet S");
            if (context.consume("SonyEricssonLT22i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia P");
            if (context.consume("SonyEricssonLT15a", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Arc");
            if (context.consume("SonyEricssonE10i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia X10 Mini");
            if (context.consume("SonyEricssonU20a", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia X10 Mini Pro");
            if (context.consume("SonyEricssonMT15i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Neo");
            if (context.consume("SonyEricssonMT11i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Neo V");
            if (context.consume("SonyEricssonWT19i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia E");
            if (context.consume("SonyEricssonR800i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Play");
            if (context.consume("SonyEricssonST27i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Go");
            if (context.consume("SonyEricssonE10a", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia X10 Mini");
            if (context.consume("SonyEricssonX10i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia X10");
            if (context.consume("SonyEricssonX10a", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia X10a");
            if (context.consume("SonyEricssonSO-01B", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia X10");
            if (context.consume("SonyEricssonR800a", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Play 4G");
            if (context.consume("SonyEricssonR800x", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Play");
            if (context.consume("SonyEricssonE15a", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia X8");
            if (context.consume("SonyEricssonE15i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia X8");
            if (context.consume("SonyEricssonMK16i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Pro");
            if (context.consume("SonyEricssonLT15i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Arc");
            if (context.consume("SonyEricssonST18i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Ray");
            if (context.consume("SonyEricssonST18a", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Ray");
            if (context.consume("SonyEricssonSK17i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Mini Pro");
            if (context.consume("SonyEricssonLT26i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia S");
            if (context.consume("SonyEricssonST25i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia U");
            if (context.consume("SonyEricssonLT18i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Arc S");
            if (context.consume("SO-01C", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia arc");
            if (context.consume("LT26i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia S");
            //TODO: UNTESTED
            if (context.consume("WT19i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Live with Walkman");

            // Sharp
            if (context.consume("SBM106SH", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SHARP,"SBM106SH");

            // HTC
            if (context.consume("Sprint APX515CKT", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Evo 3D X515xkt");
            if (context.consume("Sprint APA9292KT", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Evo 4G");
            if (context.consume("Sprint APA7373KT", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"EVO Shift 4G");
            if (context.consume("EVO ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Evo 4G");
            if (context.consume("HTC Inspire 4G ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Inspire 4G");

            if (context.consume("ADR6300", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Droid Incredible");
            if (context.consume("pcdadr6350", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"ADR6350");
            if (context.consume("PC36100", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"One XL");
            if (context.consume("IncredibleS_S710e", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Incredible S");
            if (context.consume("HTL21", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"J Butterfly");
            if (context.consume("(HTC[ _])?EVO( )?3D[ _]X515m.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Evo 3D X515m");
            if (context.consume("(HTC_)?Amaze_4G.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Amaze 4G");
            if (context.getUA().indexOf("HTC")>0) {
                if (context.consume("HTC_Flyer_P512_NA ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Flyer");
                if (context.consume("HTC[_ ]Dream .*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Dream");
                if (context.consume("HTC_S510b ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Rhyme");
                if (context.consume("HTC Liberty ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Liberty/Aria/Intruder/A6366");
                if (context.consume("HTC_WildfireS", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Wildfire S (Marvel)");
                if (context.consume("HTCA510e/1.0", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"WildFire");
                if (context.consume("HTCA510e", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Wildfire (Buzz)");
                if (context.consume("HTC[_ ]Sensation[_ ]4G.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Sensation 4G");
                if (context.consume("HTC_PH39100/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Vivid");
                if (context.consume("HTC_T120C ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"One V");
                if (context.consume("HTC_One_X", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"One X");
                if (context.consume("HTC EVA_UL", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"One X Evita");
                if (context.consume("HTC_One_S", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"One S");
                if (context.consume("HTC_DesireS_S510e", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire S");
                if (context.consume("HTC/DesireS/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire S");
                if (context.consume("HTC_DesireHD_A9191", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire HD");
                if (context.consume("HTC_C715c", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"EVO Design 4G");
                if (context.consume("HTC Sensation Z710e", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Sensation Z710e");
                if (context.consume("HTC Glacier", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Glacier");
                if (context.consume("HTC_Rhyme_S510b", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Rhyme");
                if (context.consume("HTC/WildfireS/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Wildfire S");
                if (context.consume("HTC-PG762 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Wildfire S");
                if (context.consume("HTC/Sensation/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Sensation");
                if (context.consume("HTC_SensationXL_Beats-", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Sensation XL Beats");
                if (context.consume("HTC One X", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"One X");
                if (context.consume("HTC Click-", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Click/Tattoo");
                if (context.consume("HTC Incredible S", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Incredible S");
                if (context.consume("HTC Desire HD", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire HD");
                if (context.consume("HTC HD2", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"HD2/Leo");
                if (context.consume("HTC[_ ]Wildfire[-_ ].*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Wildfire");
                if (context.consume("HTC Desire C", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire C");
                if (context.consume("HTC_DesireZ_", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire Z");
                if (context.consume("HTC-A7275", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire Z");
                if (context.consume("HTC Desire ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire");
                if (context.consume("HTC_Desire", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire");
                if (context.consume("HTC Hero ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Hero");
                if (context.consume("HTC Vision ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire Z");
                if (context.consume("HTC Legend ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Legend");
                if (context.consume("HTC One S ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"One S");
                if (context.consume("HTC[_ ]One[_ ]V .*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"One V");
                if (context.consume("HTC Bravo ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire");
                if (context.consume("HTC Salsa C510b ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Salsa");
                if (context.consume("HTC-A9192/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                    context.consume("Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
                    return new Device(arm,DeviceType.PHONE,Brand.HTC,"Inspire 4G");
                }
                if (context.consume("HTC-A6366/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                    context.consume("Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
                    return new Device(arm,DeviceType.PHONE,Brand.HTC,"Liberty/Aria/Intruder/A6366");
                }


            }
            if (context.consume("ADR6350 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Droid Incredible 2");
            if (context.consume("A6277 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                context.consume("APA6277KT", MatchingType.EQUALS, MatchingRegion.REGULAR);
                return new Device(arm,DeviceType.PHONE,Brand.HTC,"Hero");
            }

            if (context.consume("HTC Magic ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Magic");
            // LG
            {
                Device res = null;
                if (context.consume("LG-MS770 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Motion 4G");
                if (context.consume("Optimus 2X", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus 2X");
                if (context.consume("LG-L[GS]855.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Marquee");
                if (context.consume("LG-LU6500", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus Q2");
                if (context.consume("LG-LS840", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Viper");
                if (context.consume("LG-MS690", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus M");
                if (context.consume("LG-MS695", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus M+");

                if (context.consume("LG-P350", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus Me");
                if (context.consume("LG-P500", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus One");
                if (context.consume("LG-P509", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus T");
                if (context.consume("LG-P700", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus L7");
                if (context.consume("LG-P870", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Escape");
                if (context.consume("LG-P880", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus 4X HD");
                if (context.consume("LG-P920", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus 3D");
                if (context.consume("LG-P925", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Thrill 4G");
                if (context.consume("LG-P970", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus Black");
                if (context.consume("LG-P990", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus 2X");
                if (context.consume("LG-P999", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"G2x");
                if (context.consume("LG-US670", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus U");
                if (context.consume("LG-GT540", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus GT540");
                if (context.consume("LG-E400", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus L3");
                if (context.consume("LG-E739", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"myTouch");
                if (context.consume("LG-C800 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"myTouch Q");
                if (context.consume("LG-VS700", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Enlighten");
                if (context.consume("LG-VM696", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus Elite");
                if (context.consume("LG Eve", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Eve");

                if (res != null) {
                    context.consume("MMS/LG-Android-MMS", MatchingType.BEGINS, MatchingRegion.REGULAR);
                    context.consume("Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
                    return res;
                }
            }

            // Google branded
            if (context.consume("Galaxy Nexus", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.GOOGLE, Brand.SAMSUNG,"Galaxy Nexus");
            if (context.consume("Nexus S", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.GOOGLE, Brand.SAMSUNG,"Nexus S");
            if (context.consume("Nexus One", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.GOOGLE, Brand.HTC,"Nexus One");
            if (context.consume("Nexus 7", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.GOOGLE, Brand.ASUS,"Nexus 7");
            if (context.consume("Nexus 4", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.GOOGLE, Brand.LG,"Nexus 4");
            if (context.consume("Nexus 10", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.GOOGLE, Brand.SAMSUNG,"Nexus 10");


            // Motorola
            if (context.contains("motorola", MatchingType.EQUALS, MatchingRegion.REGULAR) && context.contains("[0-9]+X[0-9]+", MatchingType.REGEXP, MatchingRegion.REGULAR)) {
                context.consume("motorola", MatchingType.EQUALS, MatchingRegion.REGULAR);
                context.consume("[0-9]+X[0-9]+", MatchingType.REGEXP, MatchingRegion.REGULAR);

                if (context.consume("WX445", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                    context.consume("WX445", MatchingType.EQUALS, MatchingRegion.REGULAR);
                    return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Citrus");
                }
                if (context.consume("DROIDX Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                    context.consume("DROIDX", MatchingType.EQUALS, MatchingRegion.REGULAR);
                    return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid X");
                }
            }
            if (context.consume("MZ60[14].*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.MOTOROLA,"Xoom");
            if (context.consume("MB865", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Atrix 2");
            if (context.consume("MB860", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Atrix");
            if (context.consume("MB525", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                context.consume("MOT-MB525", MatchingType.BEGINS, MatchingRegion.REGULAR);
                return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"DEFY");
            }
            if (context.consume("DROID2", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid 2");
            if (context.consume("DROID3", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid 3");
            if (context.consume("DROID4 4G", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid 4");
            if (context.consume("DROID RAZR 4G", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid Razr 4G");
            if (context.consume("DROID RAZR HD", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid Razr HD");
            if (context.consume("DROID RAZR Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid Razr");
            if (context.consume("Droid", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid");
            if (context.consume("DROID BIONIC 4G", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid Bionic 4G");
            if (context.consume("DROID BIONIC", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid Bionic");
            if (context.consume("DROID PRO", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid Pro");
            if (context.consume("DROIDX ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid X");
            if (context.consume("DROID X2 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid X2");
            if (context.consume("MOTWX435KT", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Triumph");

            // Asus
            if (context.consume("ASUS Transformer Pad TF700T", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.ASUS,"Transformer Pad Infinity");
            if (context.consume("ASUS Transformer Pad TF300T", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.ASUS,"Transformer Pad TF300T");
            if (context.consume("Transformer TF101", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.ASUS,"Eee Pad Transformer");
            if (context.consume("Transformer Prime TF201", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.ASUS,"Eee Pad Transformer Prime");

            // Acer
            if (context.consume("A700", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.ACER,"Iconia Tab A700");
            //TODO: UNTESTED
            if (context.consume("A1-810", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.ACER,"Iconia A1-810");

            // Lenovo
            if (context.consume("Lenovo P700", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.LENOVO,"P700");

            // Amazon
            if (isKindle(context,true)) {
                if (context.consume("KFTT", MatchingType.BEGINS, MatchingRegion.CONSUMED)) return new Device(arm,DeviceType.TABLET,Brand.AMAZON,"Kindle Fire");
                if (context.consume("KFJWI", MatchingType.BEGINS, MatchingRegion.CONSUMED)) return new Device(arm,DeviceType.TABLET,Brand.AMAZON,"Kindle Fire HD 8.9");
                if (context.consume("KFOTE", MatchingType.BEGINS, MatchingRegion.CONSUMED)) return new Device(arm,DeviceType.TABLET,Brand.AMAZON,"Kindle Fire (2nd gen)");
            }

            // Toshiba
            if (context.consume("IS04", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.TOSHIBA,"Regza IS04");

            // Odys
            //TODO: UNTESTED
            if (context.consume("ADM712HC", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.ODYS,"Neo X7");

            // Generic Android
            if (context.consume("Tablet", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device("",DeviceType.TABLET,Brand.UNKNOWN_ANDROID,"Unknown");
            return new Device("",DeviceType.UNKNOWN_MOBILE,Brand.UNKNOWN_ANDROID,"Unknown");
        }
        if (o.family == OSFamily.LINUX) {
            if (context.consume("Transformer TF101", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.ASUS,"Eee Pad Transformer");
        }

        if (b.family == BrowserFamily.NETFRONT) {
            String device = context.getcRegion("(SAMSUNG-)?GT-([SB][0-9][0-9][0-9][0-9])/.*", MatchingRegion.REGULAR, 2);
            if (device != null) {
                return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,device);
            }
            //if (context.consume("(SAMSUNG-)?GT-(S3310/.*", MatchingType.REGEXP, MatchingRegion.REGULAR)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"S3310");
        }

        // Apple
        if (o.family == OSFamily.IOS) {
            if (context.consume("iPod", MatchingType.EQUALS, MatchingRegion.PARENTHESIS) ||
                    context.consume("device", MatchingType.EQUALS, MatchingRegion.PARENTHESIS) || // First gen ipod touch
                    context.consume("iPod touch", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                String dev = "iPod Touch";
                if (context.getUA().indexOf("iPod2,1")>-1) {
                    context.consume("iPod2,1", MatchingType.REGEXP, MatchingRegion.BOTH);
                    dev = "iPod Touch (2nd gen)";
                }


                return new Device(arm, DeviceType.PHONE,Brand.APPLE,dev);
            }
            if (context.consume("iPad", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm, DeviceType.TABLET,Brand.APPLE,"iPad");
            if (context.consume("iPhone", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                String dev = "iPhone";
                if (context.getUA().indexOf("iPhone3,")>-1) {
                    context.consume("iPhone3,[123]", MatchingType.REGEXP, MatchingRegion.BOTH);
                    dev = "iPhone 4";
                }
                if (context.getUA().indexOf("iPhone5,")>-1) {
                    context.consume("iPhone5,[12]", MatchingType.REGEXP, MatchingRegion.BOTH);
                    dev = "iPhone 5";
                }
                if (context.getUA().indexOf("iPhone1,1")>-1) {
                    context.consume("iPhone1,1", MatchingType.REGEXP, MatchingRegion.BOTH);
                    dev = "iPhone Edge";
                }
                if (context.getUA().indexOf("iPhone1,2")>-1) {
                    context.consume("iPhone1,2", MatchingType.REGEXP, MatchingRegion.BOTH);
                    dev = "iPhone 3G";
                }
                if (context.getUA().indexOf("iPhone2,1")>-1) {
                    context.consume("iPhone2,1", MatchingType.REGEXP, MatchingRegion.BOTH);
                    dev = "iPhone 3GS";
                }
                if (context.getUA().indexOf("iPhone4,1")>-1) {
                    context.consume("iPhone4,1", MatchingType.REGEXP, MatchingRegion.BOTH);
                    dev = "iPhone 4S";
                }

                if (context.contains("com.google.GooglePlus/", MatchingType.CONTAINS, MatchingRegion.CONSUMED)) {
                    if (context.consume("iPhone4S", MatchingType.EQUALS, MatchingRegion.PARENTHESIS))
                        dev = "iPhone 4S";
                    else if (context.consume("iPhone5", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))
                        dev = "iPhone 5";
                    else if (context.consume("iPhoneUnknown", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))
                        ;
                }
                return new Device(arm, DeviceType.PHONE,Brand.APPLE,dev);
            }
        }

        // BlackBerry
        if (o.vendor == Brand.RIM) {
            context.consume("VendorID/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            if (context.consume("BlackBerry 9650", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Bold 9650");
            if (context.consume("BlackBerry 9670", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Style 9670");
            if (context.consume("BlackBerry 9700", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Bold 9700");
            if (context.consume("BlackBerry 9300", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Curve 9300");
            if (context.consume("BlackBerry 9790", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Bold 9790");
            if (context.consume("BlackBerry 9780", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Bold 9780");
            if (context.consume("BlackBerry 9330", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Curve 3G 9330");
            if (context.consume("BlackBerry 9320", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Curve 9320");
            if (context.consume("BlackBerry 9380", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Curve 9380");
            if (context.consume("BlackBerry 9360", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Curve 9360");
            if (context.consume("BlackBerry 9930", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Bold 9930");
            if (context.consume("BlackBerry 9900", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Bold 9900");
            if (context.consume("BlackBerry 9220", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Curve 9220");
            if (context.consume("BlackBerry 9800", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Torch 9800");
            if (context.consume("BlackBerry 9860", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Torch 9860");
            if (context.consume("BlackBerry 9810", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Torch 9810");
        }
        if (context.consume("PlayBook", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.RIM,"PlayBook");
        if (context.contains("BlackBerry", MatchingType.EQUALS, MatchingRegion.CONSUMED)) {
            return new Device(arm, DeviceType.PHONE, Brand.RIM, "");
        }


        // Motorola
        if (context.consume("MOT-RAZRV3", MatchingType.BEGINS, MatchingRegion.REGULAR)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"RAZR v3");
        if (context.consume("MOT-RAZRV6", MatchingType.BEGINS, MatchingRegion.REGULAR)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"RAZR v6");

        // Sharp devices
        if (context.getUA().startsWith("SHARP-TQ-")) {
            if (context.consume("SHARP-TQ-GX20/", MatchingType.BEGINS, MatchingRegion.REGULAR))
                return new Device(arm,DeviceType.PHONE,Brand.SHARP,"TQ GX20");
            if (context.consume("SHARP-TQ-GX10i/", MatchingType.BEGINS, MatchingRegion.REGULAR))
                return new Device(arm,DeviceType.PHONE,Brand.SHARP,"TQ GX10i");
            if (context.consume("SHARP-TQ-GX-21/", MatchingType.BEGINS, MatchingRegion.REGULAR))
                return new Device(arm,DeviceType.PHONE,Brand.SHARP,"TQ GX21");
            if (context.consume("SHARP-TQ-GX17/", MatchingType.BEGINS, MatchingRegion.REGULAR))
                return new Device(arm,DeviceType.PHONE,Brand.SHARP,"TQ GX17");
            if (context.consume("SHARP-TQ-GX10/", MatchingType.BEGINS, MatchingRegion.REGULAR))
                return new Device(arm,DeviceType.PHONE,Brand.SHARP,"TQ GX10");
            if (context.consume("SHARP-TQ-GX12/", MatchingType.BEGINS, MatchingRegion.REGULAR))
                return new Device(arm,DeviceType.PHONE,Brand.SHARP,"TQ GX12");
            if (context.consume("SHARP-TQ-GZ100T/", MatchingType.BEGINS, MatchingRegion.REGULAR))
                return new Device(arm,DeviceType.PHONE,Brand.SHARP,"TQ GZ100T");
            if (context.consume("SHARP-TQ-GZ100/", MatchingType.BEGINS, MatchingRegion.REGULAR))
                return new Device(arm,DeviceType.PHONE,Brand.SHARP,"TQ GZ100");
            if (context.consume("SHARP-TQ-GX15/", MatchingType.BEGINS, MatchingRegion.REGULAR))
                return new Device(arm,DeviceType.PHONE,Brand.SHARP,"TQ GX15");
            if (context.consume("SHARP-TQ-GX30i", MatchingType.BEGINS, MatchingRegion.REGULAR))
                return new Device(arm,DeviceType.PHONE,Brand.SHARP,"TQ GX30i");
        }
        if (context.consume("Vodafone/Sharp802SH/", MatchingType.BEGINS, MatchingRegion.REGULAR)) {
            return new Device(arm,DeviceType.PHONE,Brand.SHARP,"802SH");
        }


        // Consoles
        if (context.consume("Nintendo WiiU", MatchingType.EQUALS, MatchingRegion.CONSUMED)) return new Device("PowerPC",DeviceType.CONSOLE,Brand.NINTENDO,"Wii U");
        if (context.consume("Nintendo Wii", MatchingType.EQUALS, MatchingRegion.CONSUMED)) return new Device("PowerPC",DeviceType.CONSOLE,Brand.NINTENDO,"Wii");
        if (context.consume("Nintendo DSi", MatchingType.EQUALS, MatchingRegion.CONSUMED)) return new Device(arm,DeviceType.CONSOLE,Brand.NINTENDO,"DSi");
        if (context.consume("Super_Nintendo", MatchingType.EQUALS, MatchingRegion.REGULAR)) return new Device(arm,DeviceType.CONSOLE,Brand.NINTENDO,"Super Nintendo");
        if (context.consume("Nintendo 3DS", MatchingType.EQUALS, MatchingRegion.CONSUMED)) return new Device(arm,DeviceType.CONSOLE,Brand.NINTENDO,"3DS");
        if (context.consume("PlayStation Vita", MatchingType.BEGINS, MatchingRegion.CONSUMED)) return new Device(arm,DeviceType.CONSOLE,Brand.SONY,"PlayStation Vita ");
        if (context.consume("PLAYSTATION 3", MatchingType.BEGINS, MatchingRegion.CONSUMED)) return new Device("Cell",DeviceType.CONSOLE,Brand.SONY,"PlayStation 3");
        if (context.consume("PlayStation Portable", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            context.consume("PSP", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            return new Device("MIPS",DeviceType.CONSOLE,Brand.SONY,"PlayStation Portable");
        }

        // WinMo
        if (o.family == OSFamily.WINDOWS_MOBILE) {
            if (context.getcNextTokens(new Matcher[] {new Matcher("HTC",MatchingType.EQUALS),
                new Matcher("PI86100",MatchingType.EQUALS)
            }, MatchingRegion.PARENTHESIS)!=null)
            return new Device(arm,DeviceType.PHONE,Brand.HTC,"Titan II");
            if (context.consume("(HTC_)?HD2_T8585.*", MatchingType.REGEXP, MatchingRegion.BOTH) ||
                    context.consume("Vodafone/[0-9\\.]+/HTC_HD2.*", MatchingType.REGEXP, MatchingRegion.REGULAR) ||
                    context.contains("Windows Phone [0-9\\.]+ HTC_HD2.*", MatchingType.REGEXP, MatchingRegion.CONSUMED) ||
                    context.consume("T-Mobile_LEO", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))
                return new Device(arm,DeviceType.PHONE,Brand.HTC,"HD2");
            if (context.consume("T-Mobile_Rhodium", MatchingType.EQUALS, MatchingRegion.REGULAR) ||
                    context.consume("HTC_Touch_Pro2", MatchingType.BEGINS, MatchingRegion.BOTH))
                return new Device(arm,DeviceType.PHONE,Brand.HTC,"Touch Pro 2");
            if (context.consume("HD_mini_T5555", MatchingType.EQUALS, MatchingRegion.BOTH))
                return new Device(arm,DeviceType.PHONE,Brand.HTC,"HD Mini");

            if (o.version.equals("CE")) {
                context.consume("PPC" , MatchingType.EQUALS, MatchingRegion.PARENTHESIS ); // Pocket PC
                if (context.consume("Palm750/v0100" , MatchingType.BEGINS, MatchingRegion.REGULAR ))
                    return new Device(arm,DeviceType.PHONE,Brand.PALM,"Treo 750");
                if (context.consume("HTC_Snap_S52[0-9]", MatchingType.REGEXP, MatchingRegion.REGULAR))
                    return new Device(arm,DeviceType.PHONE,Brand.HTC,"Snap");
                if (context.consume("HTC_TyTN", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))
                    return new Device(arm,DeviceType.PHONE,Brand.HTC,"TyTN");
                if (context.consume("HTC_Touch2_T3333", MatchingType.EQUALS, MatchingRegion.REGULAR))
                    return new Device(arm,DeviceType.PHONE,Brand.HTC,"Touch 2");
                if (context.consume("HTC_Maple_S520", MatchingType.EQUALS, MatchingRegion.REGULAR))
                    return new Device(arm,DeviceType.PHONE,Brand.HTC,"Maple");
                if (context.consume("HTC_Touch_Diamond2_T5353", MatchingType.EQUALS, MatchingRegion.REGULAR))
                    return new Device(arm,DeviceType.PHONE,Brand.HTC,"Touch Diamond2");



                if (context.consume("acer_S200", MatchingType.EQUALS, MatchingRegion.REGULAR))
                    return new Device(arm,DeviceType.PHONE,Brand.ACER,"neoTouch");

                if (context.getcNextTokens(new Matcher[] {new Matcher("LGE",MatchingType.EQUALS),
                    new Matcher("VS750",MatchingType.BEGINS)
                }, MatchingRegion.REGULAR)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.LG,"Fathom");
                if (context.consume("LG-GW550", MatchingType.EQUALS, MatchingRegion.REGULAR))
                    return new Device(arm,DeviceType.PHONE,Brand.LG,"GW550");



                if (context.consume("SAMSUNG-GT-i8000", MatchingType.BEGINS, MatchingRegion.REGULAR))
                    return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Omnia II");
                if (context.consume("SAMSUNG-GT-B7610", MatchingType.BEGINS, MatchingRegion.REGULAR) ||
                        context.consume("SAMSUNG-GT-B73[2-3]0.*", MatchingType.REGEXP, MatchingRegion.REGULAR))
                    return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Omnia Pro");
                if (context.consume("SAMSUNG-SGH-i710", MatchingType.BEGINS, MatchingRegion.REGULAR))
                    return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"i710");
                if (context.consume("SAMSUNG-SGH-I607", MatchingType.BEGINS, MatchingRegion.REGULAR))
                    return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"BlackJack");
                if (context.consume("SAMSUNG-SCH-i220", MatchingType.BEGINS, MatchingRegion.REGULAR))
                    return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Code");

                if (context.consume("SonyEricssonX1a", MatchingType.BEGINS, MatchingRegion.REGULAR))
                    return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia X1");
                if (context.consume("SonyEricssonM1a", MatchingType.BEGINS, MatchingRegion.REGULAR)) {
                    context.consume("Browser/Mozilla/4.0", MatchingType.EQUALS, MatchingRegion.REGULAR);
                    return new Device(arm,DeviceType.PHONE,Brand.SONY,"Aspen Faith");
                }

                return new Device("",DeviceType.PHONE,Brand.UNKNOWN,"");

            } else {
                if (context.consume("SonyEricssonM1i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))
                    return new Device(arm,DeviceType.PHONE,Brand.SONY,"Aspen M1i");

                if (context.consume("Touch_HD_T8282", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))
                    return new Device(arm,DeviceType.PHONE,Brand.HTC,"Focus Flash");


                if (context.getcNextTokens(new Matcher[] {new Matcher("HTC",MatchingType.EQUALS),
                    new Matcher("mwp6985",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null ||
                context.getcNextTokens(new Matcher[] {new Matcher("HTC",MatchingType.EQUALS),
                                           new Matcher("7 Trophy",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.HTC,"7 Trophy");
                if (context.getcNextTokens(new Matcher[] {new Matcher("HTC",MatchingType.EQUALS),
                    new Matcher("T8697",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null ||
                context.getcNextTokens(new Matcher[] {new Matcher("HTC",MatchingType.EQUALS),
                                           new Matcher("7 Mozart",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.HTC,"7 Mozart");
                if (context.getcNextTokens(new Matcher[] {new Matcher("HTC",MatchingType.EQUALS),
                    new Matcher("Radar",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.HTC,"Radar");
                if (context.getcNextTokens(new Matcher[] {new Matcher("HTC",MatchingType.EQUALS),
                    new Matcher("T8788",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.HTC,"7 Surround");
                if (context.getcNextTokens(new Matcher[] {new Matcher("HTC",MatchingType.EQUALS),
                    new Matcher("HD7 T9292",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.HTC,"HD7 T9292");
                if (context.getcNextTokens(new Matcher[] {new Matcher("HTC",MatchingType.EQUALS),
                    new Matcher("7 Pro",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.HTC,"7 Pro");
                if (context.getcNextTokens(new Matcher[] {new Matcher("HTC",MatchingType.EQUALS),
                    new Matcher("TITAN",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.HTC,"Titan");
                if (context.getcNextTokens(new Matcher[] {new Matcher("HTC",MatchingType.EQUALS),
                    new Matcher("HD7",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.HTC,"Schubert (HD7)");
                if (context.contains("Windows Phone 8X by HTC",MatchingType.EQUALS,MatchingRegion.CONSUMED) &&
                        context.consume("HTC",MatchingType.EQUALS,MatchingRegion.PARENTHESIS))
                    return new Device(arm,DeviceType.PHONE,Brand.HTC,"8X");

                if (context.getcNextTokens(new Matcher[] {new Matcher("NOKIA",MatchingType.EQUALS),
                    new Matcher("Lumia 822",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.NOKIA,"Lumia 822");
                if (context.getcNextTokens(new Matcher[] {new Matcher("NOKIA",MatchingType.EQUALS),
                    new Matcher("Lumia 920",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.NOKIA,"Lumia 920");
                if (context.getcNextTokens(new Matcher[] {new Matcher("NOKIA",MatchingType.EQUALS),
                    new Matcher("Lumia 900",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.NOKIA,"Lumia 900");
                if (context.getcNextTokens(new Matcher[] {new Matcher("NOKIA",MatchingType.EQUALS),
                    new Matcher("Lumia 800",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.NOKIA,"Lumia 800");
                if (context.getcNextTokens(new Matcher[] {new Matcher("NOKIA",MatchingType.EQUALS),
                    new Matcher("Lumia 710",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.NOKIA,"Lumia 710");
                if (context.getcNextTokens(new Matcher[] {new Matcher("NOKIA",MatchingType.EQUALS),
                    new Matcher("Lumia 820",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.NOKIA,"Lumia 820");
                if (context.getcNextTokens(new Matcher[] {new Matcher("NOKIA",MatchingType.EQUALS),
                    new Matcher("Lumia 610",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.NOKIA,"Lumia 610");

                if (context.getcNextTokens(new Matcher[] {new Matcher("SAMSUNG",MatchingType.EQUALS),
                    new Matcher("SGH-i917",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Focus");
                if (context.getcNextTokens(new Matcher[] {new Matcher("SAMSUNG",MatchingType.EQUALS),
                    new Matcher("SGH-i677",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Focus Flash");
                if (context.getcNextTokens(new Matcher[] {new Matcher("SAMSUNG",MatchingType.EQUALS),
                    new Matcher("OMNIA7",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Omnia 7");

                if (context.getcNextTokens(new Matcher[] {new Matcher("LG",MatchingType.EQUALS),
                    new Matcher("LG-C900",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus 7Q / Quantum");
                if (context.getcNextTokens(new Matcher[] {new Matcher("LG",MatchingType.EQUALS),
                    new Matcher("LG-E900",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus 7");

                if (context.getcNextTokens(new Matcher[] {new Matcher("Acer",MatchingType.EQUALS),
                    new Matcher("Allegro",MatchingType.EQUALS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.ACER,"Allegro");


                if (context.consume("Asus;Galaxy6",MatchingType.EQUALS, MatchingRegion.REGULAR))
                    return new Device(arm,DeviceType.PHONE,Brand.ASUS,"Galaxy 6");
                if (context.consume("garmin-asus-Nuvifone",MatchingType.BEGINS, MatchingRegion.PARENTHESIS))
                    return new Device(arm,DeviceType.PHONE,Brand.GARMIN,Brand.ASUS,"Nuvifone");

            }
            String arch = "";
            if (context.contains("ARM", MatchingType.EQUALS, MatchingRegion.CONSUMED)) {
                arch += "ARM";
            }

            return new Device(arch,DeviceType.UNKNOWN_MOBILE,Brand.UNKNOWN,"");
        }



        // Bada
        if (o.family == OSFamily.BADA) {
            if (context.contains("SAMSUNG[ -]GT-.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS) ||
                    context.contains("GT-", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                if (context.consume("(SAMSUNG[ -])?GT-S5380.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Wave Y");
                if (context.consume("(SAMSUNG[ -])?GT-S8500.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Wave");
                if (context.consume("(SAMSUNG[ -])?GT-S8530.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Wave 2");
                if (context.consume("(SAMSUNG[ -])?GT-S5750.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Wave 575");
                if (context.consume("(SAMSUNG[ -])?GT-S5253.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Wave 525");
                if (context.consume("(SAMSUNG[ -])?GT-S7230.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Wave 723");
                if (context.consume("(SAMSUNG[ -])?GT-S8600.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Wave 3");
                if (context.consume("(SAMSUNG[ -])?GT-S5780.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Wave 578");
                if (context.consume("(SAMSUNG[ -])?GT-S5330.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Wave 533 / Wave 2 Pro");
            }
        }
        // Other samsung OS
        if (context.getUA().startsWith("SAMSUNG-GT-") || context.getUA().startsWith("samsung-gt") || context.contains("SPH-M[0-9]{3}", MatchingType.REGEXP, MatchingRegion.BOTH)) {
            Device device = new Device(arm, DeviceType.PHONE, Brand.SAMSUNG, "");
            if (context.consume("SAMSUNG-GT-S5263/", MatchingType.BEGINS, MatchingRegion.REGULAR)) device.device = "Star II";
            if (context.consume("SAMSUNG-GT-S5230/", MatchingType.BEGINS, MatchingRegion.REGULAR)) device.device = "Player One";
            if (context.consume("SPH-M810", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) device.device = "Instinct Mini (S30)";
            if (context.consume("SPH-M800", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) device.device = "Instinct";
            if (context.consume("SPH-M570", MatchingType.EQUALS, MatchingRegion.REGULAR)) device.device = "Restore";
            if (context.consume("samsung-gt-s5350/", MatchingType.BEGINS, MatchingRegion.REGULAR)) device.device = "Shark";
            if (device.device.length()>0) {
                context.consume("SAMSUNG", MatchingType.EQUALSIGNORECASE, MatchingRegion.PARENTHESIS);
                if (o.family == OSFamily.UNKNOWN) {
                    o.family = OSFamily.OTHER;
                    o.vendor = Brand.SAMSUNG;
                    o.description = "Proprietary OS";
                }
                if (b.family == BrowserFamily.UNKNOWN && (ver = context.getcVersionAfterPattern("Dolfin/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
                    b.description = "Dolfin " + ver;
                    b.family = BrowserFamily.OTHER;
                    b.renderingEngine = "WebKit";
                    b.vendor = Brand.SAMSUNG;
                } else if (b.family == BrowserFamily.UNKNOWN && (ver = context.getcVersionAfterPattern("Jasmine/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
                    // Not so sure this is actually a web browser...
                    b.description = "Jasmine " + ver;
                    b.family = BrowserFamily.OTHER;
                    b.renderingEngine = "";
                    b.vendor = Brand.SAMSUNG;
                } else if (b.family == BrowserFamily.UNKNOWN && (ver = context.getcVersionAfterPattern("Browser",  MatchingType.BEGINS, MatchingRegion.REGULAR, 2))!=null) {
                    // Not so sure this is actually a web browser...
                    b.description = "Browser " + ver;
                    b.family = BrowserFamily.OTHER;
                    b.renderingEngine = "";
                    b.vendor = Brand.SAMSUNG;
                } else if (b.family == BrowserFamily.UNKNOWN && (ver = context.getcVersionAfterPattern("TELECA-/",  MatchingType.BEGINS, MatchingRegion.REGULAR, 2))!=null) {
                    b.description = "Teleca " + ver;
                    b.family = BrowserFamily.OTHER;
                    b.renderingEngine = "";
                    b.vendor = Brand.OBIGO;
                    context.consume("Teleca/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
                }
                return device;
            }
        }

        // Other phones
        if (context.contains("SANYO", MatchingType.BEGINSIGNORECASE, MatchingRegion.BOTH)) {
            Device res = null;
            if (context.getcNextTokens(new Matcher[] {new Matcher("Boost",MatchingType.EQUALS),
                new Matcher("SCP6760",MatchingType.EQUALS)
            }, MatchingRegion.REGULAR)!=null)
            res = new Device(arm,DeviceType.PHONE,Brand.SANYO,"Incognito");
            if (context.getcNextTokens(new Matcher[] {new Matcher("Sprint",MatchingType.EQUALS),
                new Matcher("SCP-6780",MatchingType.EQUALS)
            }, MatchingRegion.REGULAR)!=null)
            res = new Device(arm,DeviceType.PHONE,Brand.SANYO,"Innuendo");
            if (context.contains("Sanyo",MatchingType.EQUALS,MatchingRegion.PARENTHESIS) &&
                    context.consume("PL2700",MatchingType.EQUALS,MatchingRegion.REGULAR))
                res = new Device(arm,DeviceType.PHONE,Brand.SANYO,"PL2700");

            if (context.getcNextTokens(new Matcher[] {new Matcher("Boost",MatchingType.EQUALS),
                new Matcher("SCP-2700",MatchingType.EQUALS)
            }, MatchingRegion.REGULAR)!=null)
            res = new Device(arm,DeviceType.PHONE,Brand.SANYO,"SCP 2700");
            if (context.consume("SANYO/WX310SA/2", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                context.consume("WILLCOM", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                context.consume("Mozilla/3.0", MatchingType.EQUALS, MatchingRegion.REGULAR);
                context.consume("1/1/C128", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                return new Device(arm,DeviceType.PHONE,Brand.SANYO,"WX 310");
            }
            if (context.getUA().equals("Sanyo-SCP588CN")) {
                context.consume("Sanyo-SCP588CN", MatchingType.EQUALS, MatchingRegion.REGULAR);
                return new Device(arm,DeviceType.PHONE,Brand.SANYO,"SCP 588");
            }
            if (context.getUA().equals("Sanyo-SCP6200")) {
                context.consume("Sanyo-SCP6200", MatchingType.EQUALS, MatchingRegion.REGULAR);
                return new Device(arm,DeviceType.PHONE,Brand.SANYO,"SCP 6200");
            }
            if (context.consume("Sanyo-SCP510CN/", MatchingType.BEGINS, MatchingRegion.REGULAR)) {
                return new Device(arm,DeviceType.PHONE,Brand.SANYO,"SCP 510");
            }

            if (res != null) {
                context.consume("Sanyo", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                context.consume("Mozilla/", MatchingType.BEGINS, MatchingRegion.REGULAR);
                return res;
            }
        }

        if ((ver=context.getcVersionAfterPattern("SharpWXT71/SHS001/", MatchingType.CONTAINS, MatchingRegion.BOTH)) != null) {
            return new Device(arm,DeviceType.PHONE,Brand.SHARP,"WXT71 " + ver);
        }

        if (context.consume("ZTE-C880/", MatchingType.CONTAINS, MatchingRegion.REGULAR))
            return new Device(arm,DeviceType.PHONE,Brand.ZTE,"C880");
        if (context.consume("ZTE-C70/", MatchingType.CONTAINS, MatchingRegion.REGULAR))
            return new Device(arm,DeviceType.PHONE,Brand.ZTE,"C70");

        if (context.consume("HUAWEI-M635/", MatchingType.BEGINS, MatchingRegion.REGULAR))
            return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Pinnacle M635");
        if (context.consume("HUAWEI-M735/", MatchingType.BEGINS, MatchingRegion.REGULAR)) {
            if ((ver=context.getcVersionAfterPattern("Opera/", MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                b.family = BrowserFamily.OPERA;
                b.description = "Opera " + ver;
                b.renderingEngine = "Presto";
                b.vendor = Brand.OPERA;
            }
            return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"M735");
        }
        if (context.getcNextTokens(new Matcher[] {new Matcher("Huawei",MatchingType.EQUALS),
            new Matcher("U9120/",MatchingType.BEGINS)
        }, MatchingRegion.REGULAR)!=null)
        return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"U9120");
        if (context.consume("HuaweiG2800/", MatchingType.CONTAINS, MatchingRegion.REGULAR))
            return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"G2800");

        // Generic/Odd Devices
        if ((ver = context.getcVersionAfterPattern("AlphaServer", MatchingType.CONTAINS, MatchingRegion.BOTH)) != null ||
                (ver = context.getcVersionAfterPattern("AlphaServer", MatchingType.CONTAINS, MatchingRegion.CONSUMED)) != null) {
            while (ver.length()>0) {
                if (ver.charAt(0) != '.') break;
                ver = ver.substring(1);
            }
            String device = "AlphaServer " + ver;
            if (context.consume("Powered By 64-Bit Alpha Processor", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                return new Device("64-Bit Alpha Processor",DeviceType.COMPUTER,Brand.DIGITAL_HP,device);
            } else {
                return new Device("",DeviceType.COMPUTER,Brand.DIGITAL_HP,device);
            }
        }


        // Generic OSes
        if (o.family == OSFamily.CHROMEOS) {
            if ((ver = context.getcVersionAfterPattern("CrOS", MatchingType.BEGINS, MatchingRegion.CONSUMED)) != null) {
                if (ver.contains(" "))
                    return new Device(ver.split(" ")[0],DeviceType.COMPUTER,Brand.UNKNOWN,"");
            }
        }
        if (o.family == OSFamily.WINDOWS_NT) {
            String arch = "";
            DeviceType deviceType = DeviceType.COMPUTER;
            Brand brand = Brand.WINDOWS;
            String device = "PC";

            boolean highBits = context.consume("WOW64", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            highBits |= context.consume("Win64", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            if (highBits) {
                if (context.consume("x64", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                    arch = "AMD 64bits";
                } else if (context.consume("AMD64", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                    arch = "AMD 64bits";
                } else if (context.consume("IA64", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                    arch = "Intel 64bits";
                } else {
                    arch = "64bits";
                }
            }
            if (context.contains("Powered By 64-Bit Alpha Processor", MatchingType.EQUALS, MatchingRegion.CONSUMED)) {
                arch = "64bits Alpha";
            }
            if (context.contains("Windows NT [0-9\\.]+ x64", MatchingType.REGEXP, MatchingRegion.CONSUMED)) {
                arch += " 64bits";
            }
            if (context.contains("Windows NT 6.2", MatchingType.EQUALS, MatchingRegion.CONSUMED) &&
                    context.contains("ARM", MatchingType.EQUALS, MatchingRegion.CONSUMED)) {
                arch += " ARM";
            }
            if (context.consume("Tablet PC [1-2]\\.[07]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) {
                deviceType = DeviceType.TABLET;
            }

            if (context.consume("MAAR", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                brand = Brand.ACER;
                device="Aspire";
            }
            if (context.consume("MDD[CR](JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) brand = Brand.DELL;
            if (context.consume("HP[ND]TDF(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) brand = Brand.HP;
            if (context.consume("CMNTDF", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) brand = Brand.COMPAQ;
            if (context.consume("MAAR(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) brand = Brand.ACER;
            if (context.consume("MAS[PA](JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) brand = Brand.SONY;
            if (context.consume("MASP(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) brand = Brand.SONY;
            if (context.consume("MATB(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) brand = Brand.TOSHIBA;
            if (context.consume("ASU2(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) brand = Brand.ASUS;

            return new Device(arch.trim(),deviceType,brand,device);
        }
        if (o.family == OSFamily.WINDOWS) {
            String arch = "Intel";
            if (context.consume("Win32", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) arch += " 32 bits";
            if (context.consume("AMD64", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) arch = "AMD 64 bits";
            return new Device(arch,DeviceType.COMPUTER,Brand.UNKNOWN,"PC");
        }

        if (o.family == OSFamily.MACOSX || o.family == OSFamily.MACOS) {
            if (context.contains("Intel Mac OS X", MatchingType.BEGINS, MatchingRegion.CONSUMED))
                return new Device("Intel",DeviceType.COMPUTER,Brand.APPLE,"Macintosh");
            if (context.contains("PPC Mac OS X", MatchingType.BEGINS, MatchingRegion.CONSUMED))
                return new Device("Power PC",DeviceType.COMPUTER,Brand.APPLE,"Macintosh");
            if (context.contains("Mac_PowerPC", MatchingType.BEGINS, MatchingRegion.CONSUMED))
                return new Device("Power PC",DeviceType.COMPUTER,Brand.APPLE,"Macintosh");
        }

        if ((ver = context.getToken(new Matcher("NetBSD", MatchingType.BEGINS), MatchingRegion.CONSUMED)) != null) {
            String[]vv = ver.split(" ");
            if (vv.length == 3) {
                ver = vv[2];
            } else if (vv.length == 2) {
                ver = vv[1];
            } else ver = "";
            return new Device(ver,DeviceType.COMPUTER,Brand.UNKNOWN,"");
        }

        if (o.family == OSFamily.LINUX) {
            if ((context.contains("Linux i686", MatchingType.BEGINS, MatchingRegion.CONSUMED) ||
                    context.consume("Linux i686", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) &&
                    context.consume("x86_64", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))
                return new Device("x86_64",DeviceType.COMPUTER,Brand.UNKNOWN,"");
            if ((context.contains("Linux i986", MatchingType.BEGINS, MatchingRegion.CONSUMED) ||
                    context.consume("Linux i986", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)))
                return new Device("i986",DeviceType.COMPUTER,Brand.UNKNOWN,"");
            if ((context.contains("Linux ppc64", MatchingType.BEGINS, MatchingRegion.CONSUMED) ||
                    context.consume("Linux ppc64", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)))
                return new Device("PowerPC 64bits",DeviceType.COMPUTER,Brand.UNKNOWN,"");
            if (context.contains("i686 Linux", MatchingType.BEGINS, MatchingRegion.CONSUMED)) return new Device("i686",DeviceType.COMPUTER,Brand.UNKNOWN,"");
            if (context.contains("Linux amd64", MatchingType.EQUALS, MatchingRegion.CONSUMED)) return new Device("AMD 64bits",DeviceType.COMPUTER,Brand.UNKNOWN,"");
            if (context.contains("Linux [0-9.]+-[0-9]-amd64.*", MatchingType.REGEXP, MatchingRegion.CONSUMED)) return new Device("AMD 64bits",DeviceType.COMPUTER,Brand.UNKNOWN,"");
            if (context.consume("i386", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device("i386",DeviceType.COMPUTER,Brand.UNKNOWN,"");
            if (context.consume("i686", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device("i686",DeviceType.COMPUTER,Brand.UNKNOWN,"");
            if (context.consume("x86_64", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device("x86_64",DeviceType.COMPUTER,Brand.UNKNOWN,"");
            if (context.contains(".*Linux.*x86_64", MatchingType.REGEXP, MatchingRegion.CONSUMED) ||
                    context.consume (".*Linux.*x86_64", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device("x86_64",DeviceType.COMPUTER,Brand.UNKNOWN,"");
            if (context.contains("Linux", MatchingType.EQUALS, MatchingRegion.CONSUMED) &&
                    context.consume("x86_64", MatchingType.EQUALS, MatchingRegion.BOTH)) return new Device("x86_64",DeviceType.COMPUTER,Brand.UNKNOWN,"");
            if (context.contains("Linux", MatchingType.EQUALS, MatchingRegion.CONSUMED) &&
                    context.contains("x86_64", MatchingType.EQUALS, MatchingRegion.CONSUMED)) return new Device("x86_64",DeviceType.COMPUTER,Brand.UNKNOWN,"");
            if (context.contains(".*Linux.*i686", MatchingType.REGEXP, MatchingRegion.CONSUMED)) return new Device("i686",DeviceType.COMPUTER,Brand.UNKNOWN,"");
        }
        if (context.contains("IRIX", MatchingType.BEGINS, MatchingRegion.CONSUMED)) return new Device("MIPS",DeviceType.COMPUTER,Brand.SGI,"IRIX workstation");
        if (o.family == OSFamily.BEOS) {
            if (context.contains("BeOS BeBox", MatchingType.EQUALS, MatchingRegion.CONSUMED)) return new Device("PowerPC",DeviceType.COMPUTER,Brand.BE,"BeBox");
        }

        if (o.family == OSFamily.BSD) {
            if (context.contains("(Free|Open)BSD ([0-9.]+-RELEASE )?i386", MatchingType.REGEXP, MatchingRegion.CONSUMED)) return new Device("i386",DeviceType.COMPUTER,Brand.UNKNOWN,"");
            if (context.contains("(Free|Open)BSD ([0-9.]+-RELEASE )?amd64", MatchingType.REGEXP, MatchingRegion.CONSUMED)) return new Device("AMD 64bits",DeviceType.COMPUTER,Brand.UNKNOWN,"");
        }

        if (o.family == OSFamily.UNIX && o.description.equals("SunOS")) {
            if (context.contains("SunOS.*i86pc.*", MatchingType.REGEXP, MatchingRegion.CONSUMED)) return new Device("Intel x86",DeviceType.COMPUTER,Brand.UNKNOWN,"PC");
            if (context.contains(".*sun4u", MatchingType.REGEXP, MatchingRegion.CONSUMED)) return new Device("UltraSPARC", DeviceType.COMPUTER, Brand.SUN, "UltraSPARC");
            if (context.contains(".*sun4[mv]", MatchingType.REGEXP, MatchingRegion.CONSUMED)) return new Device("SPARC", DeviceType.COMPUTER, Brand.SUN, "SPARC");
        }

        // Fallbacks
        if (context.contains("Opera Mobi", MatchingType.BEGINS, MatchingRegion.CONSUMED) ||
                context.contains("Opera Mini", MatchingType.BEGINS, MatchingRegion.CONSUMED))
            return new Device("",DeviceType.UNKNOWN_MOBILE,Brand.UNKNOWN,"");

        if (o.vendor == Brand.NOKIA) {
            return new Device(arm,DeviceType.PHONE,Brand.UNKNOWN,"");
        }

        if (context.consume("X11", MatchingType.EQUALS, MatchingRegion.PARENTHESIS) ||
                context.contains("X11", MatchingType.EQUALS, MatchingRegion.CONSUMED))
            return new Device("",DeviceType.COMPUTER,Brand.UNKNOWN,"");

        if (context.consume("Danger hiptop [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) {
            return new Device("",DeviceType.UNKNOWN_MOBILE,Brand.UNKNOWN,"T-Mobile Sidekick");
        }

        return new Device("",DeviceType.UNKNOWN,Brand.UNKNOWN,"");
    }


    static UserAgentDetectionResult getLibraries(UserAgentContext context) {
        String ua = context.getUA();
        int pos=0;
        String ver,token;

        UserAgentDetectionResult res = new UserAgentDetectionResult(
            new Device("",DeviceType.COMPUTER,Brand.UNKNOWN,""),
            new Browser(Brand.UNKNOWN,BrowserFamily.UNKNOWN,"","n/a"),
            new OS(Brand.LINUX,OSFamily.LINUX,"Linux",""));



        if ((ver=context.getcVersionAfterPattern("libcurl/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
            String archTotal = context.getcToken("",MatchingType.ALWAYS_MATCH, MatchingRegion.PARENTHESIS);
            String arch;
            if ((pos=archTotal.indexOf("-"))>-1) {
                arch = archTotal.substring(0,pos);
            } else {
                arch = "";
            }
            res.device.architecture = arch;
            res.browser.family = BrowserFamily.ROBOT;
            res.browser.description = "curl " + ver;

            context.consume("curl/",MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("NSS/",MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("zlib/",MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("libidn/",MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("libssh2/",MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("OpenSSL/",MatchingType.BEGINS, MatchingRegion.REGULAR);

            if (archTotal.indexOf("-pc-")>-1) {
                res.device.device = "PC";
            }

            if (archTotal.endsWith("-redhat-linux-gnu")) {
                res.operatingSystem.version = ("Red Hat " + arch).trim();
                return res;
            } else if (archTotal.endsWith("-pc-win32")) {
                res.device.setBrandAndManufacturer(Brand.WINDOWS);
                res.operatingSystem.family = OSFamily.WINDOWS;
                res.operatingSystem.description = "Windows";
                res.operatingSystem.version = arch;
                return res;
            } else if (archTotal.endsWith("pc-mingw32msvc")) {
                res.device.setBrandAndManufacturer(Brand.WINDOWS);
                res.operatingSystem.family = OSFamily.WINDOWS;
                res.operatingSystem.description = "Windows";
                res.operatingSystem.version = (arch + " through MinGW").trim();
                return res;
            } else if ((pos=archTotal.indexOf("-apple-darwin"))>-1) {
                res.device.setBrandAndManufacturer(Brand.APPLE);
                res.device.device = "Macintosh";
                res.operatingSystem.family = OSFamily.MACOSX;
                res.operatingSystem.description = "Mac OS";
                res.operatingSystem.version =  "darwin "+getVersionNumber(archTotal,pos+13)+ (arch.equals("universal")?(""):(" " + arch));
                return res;
            } else if (archTotal.endsWith("-linux-gnu")) {
                res.operatingSystem.version = arch;
                return res;
            } else if ((pos=archTotal.indexOf("-portbld-freebsd"))>-1) {
                res.operatingSystem.family = OSFamily.BSD;
                res.operatingSystem.description = "FreeBSD";
                res.operatingSystem.version =  (getVersionNumber(archTotal,pos+16) + " "+arch).trim();
                return res;
            }
        } else if ((ver=context.getcVersionAfterPattern("Wget/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
            res.browser.family = BrowserFamily.ROBOT;
            res.browser.description = "wget " + ver;

            if (context.consume("Red Hat modified",MatchingType.EQUALS, MatchingRegion.PARENTHESIS) ||
            context.getcNextTokens(new Matcher[] {new Matcher("Red",MatchingType.EQUALS),
                                       new Matcher("Hat",MatchingType.EQUALS),
                                       new Matcher("modified",MatchingType.EQUALS)
            }, MatchingRegion.REGULAR)!=null) {
                res.operatingSystem.version = "Red Hat";
                return res;
            }
            else if (context.consume("linux-gnu",MatchingType.EQUALS, MatchingRegion.BOTH)) {
                return res;
            } else if ((ver=context.getcVersionAfterPattern("freebsd",MatchingType.BEGINS, MatchingRegion.BOTH))!=null) {
                res.operatingSystem.family = OSFamily.BSD;
                res.operatingSystem.description = "FreeBSD";
                res.operatingSystem.version = ver;
                return res;
            } else if (context.consume("cygwin",MatchingType.EQUALS, MatchingRegion.BOTH)) {
                res.device.setBrandAndManufacturer(Brand.WINDOWS);
                res.operatingSystem.family = OSFamily.WINDOWS;
                res.operatingSystem.description = "Windows";
                res.operatingSystem.version = "through cygwin";
                return res;
            } else {
                res.operatingSystem = new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"","");
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
                       new Device("",DeviceType.COMPUTER,Brand.UNKNOWN,"Broken link finder"),
                       new Browser(Brand.UNKNOWN,BrowserFamily.ROBOT,"Xenu Link Sleuth " + token,"n/a"),
                       new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"",""));
        }


        return null;
    }


    static Locale getLocale(String s, UserAgentContext context) {
        if (s.equals("LG")) {
            if (context.contains("LG-", MatchingType.BEGINS, MatchingRegion.BOTH)) return null;
        }
        if (s.length() == 4 && s.charAt(0) == '[' && s.charAt(3) == ']') {
            Language l = LocaleHelper.getLanguage(s.substring(1,3));
            if (l != null) {
                return new Locale(l);
            }
        } else if (s.length() == 2) {
            Language l = LocaleHelper.getLanguage(s);
            if (l != null) {
                return new Locale(l);
            }
        } else if (s.length() == 5 && (s.charAt(2) == '-' || s.charAt(2) == '_')) {
            Language l = LocaleHelper.getLanguage(s.substring(0,2));
            Country c = LocaleHelper.getCountry(s.substring(3,5));
            if (l != null && c != null) {
                return new Locale(l,c);
            }
        } else if (s.length() == 7 && (s.charAt(3) == '-' || s.charAt(3) == '_') && s.charAt(0) == '[' && s.charAt(6) == ']') {
            Language l = LocaleHelper.getLanguage(s.substring(1,3));
            Country c = LocaleHelper.getCountry(s.substring(4,6));
            if (l != null && c != null) {
                return new Locale(l,c);
            }
        }

        if (s.contains(",")) {
            String[]langs = s.split(",");
            boolean ok = true;
            int pos = 0, curPos = 0;
            for (String lang : langs) {
                lang = lang.trim();
                switch(lang.length()) {
                case 0:
                    if (curPos == 0 && langs.length>pos+1) pos++;
                    break;
                case 2:
                    ok = ok && LocaleHelper.getLanguage(lang)!=null;
                    break;
                case 5:
                    ok = ok && LocaleHelper.getLanguage(lang.substring(0,2))!=null && (lang.charAt(2)=='_' || lang.charAt(2)=='-') && LocaleHelper.getCountry(lang.substring(3,5))!=null;
                    break;
                default:
                    ok = false;
                    break;
                }
                if (!ok) break;
                curPos++;
            }
            if (ok) {
                return getLocale(langs[pos].trim(), context);
            }
        }

        return null;
    }

    static Locale getLocale(UserAgentContext context) {
        //String ua = context.getUA();
        //ua = ua.replaceAll("Windows CE","").replaceAll("Mac OS","").replaceAll("CPU OS","").replaceAll("iPhone OS","");
        //StringTokenizer stw = new StringTokenizer(ua," ;)(");
        Iterator<String> it = context.getRegularTokensIterator();
        while (it.hasNext()) {
            String s = it.next();
            Locale l = getLocale(s,context);
            if (l != null) {
                context.consume(s,MatchingType.EQUALS,MatchingRegion.REGULAR);
                return l;
            }
        }
        it = context.getParenTokensIterator();
        while (it.hasNext()) {
            String s = it.next();
            Locale l = getLocale(s,context);
            if (l != null) {
                context.consume(s,MatchingType.EQUALS,MatchingRegion.PARENTHESIS);
                return l;
            }
        }

        String token;
        if ((token = context.getToken(new Matcher(".* \\[[a-zA-Z][a-zA-Z]\\] .*", MatchingType.REGEXP), MatchingRegion.BOTH)) != null) {
            String[]sp = token.split(" ");
            for (String s : sp) {
                if (s.length() == 4 && s.charAt(0) == '[' && s.charAt(3) == ']') {
                    Language l = LocaleHelper.getLanguage(s.substring(1,3));
                    if (l != null) {
                        context.consume(s,MatchingType.EQUALS,MatchingRegion.BOTH);
                        return new Locale(l);
                    }
                }
            }
        }

        return new Locale();
    }


    static void addExtensions(UserAgentContext context, UserAgentDetectionResult res) {
        String ver;
        if (res.operatingSystem.vendor == Brand.SAMSUNG || res.operatingSystem.family == OSFamily.UNKNOWN) {
            if ((ver = context.getcVersionAfterPattern("BREW ",MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) != null ||
                    (ver = context.getcVersionAfterPattern("Brew MP ",MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) != null) {
                // http://www.brewmp.com/
                // Binary Runtime Environment for Wireless
                res.addExtension(new Extension("BREW ",ver));
            }

        }
        if ((ver = context.getcVersionAfterPattern("NexPlayer/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
            res.addExtension(new Extension("NexPlayer ",ver));
        }
        if ((ver = context.getcVersionAfterPattern("YPC ",MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) != null) {
            res.addExtension(new Extension("Yahoo! Parental Control",ver));
            context.consume("yplus ",MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
        }
        if ((ver = context.getcVersionAfterPattern("WebSlideShow/",MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
            res.addExtension(new Extension("WebSlideShow",ver));
        }
        if (context.consume("via translate.google.com",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res.addExtension(new Extension("via translate.google.com",""));
        }
        if (context.consume("SAFEXPLORER TL",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res.addExtension(new Extension("SAFEXPLORER TL"));
        }
        if ((ver = context.getcVersionAfterPattern("Profile/MIDP-",MatchingType.BEGINS, MatchingRegion.BOTH)) != null ||
                (ver = context.getcVersionAfterPattern("profile/MIDP-",MatchingType.BEGINS, MatchingRegion.BOTH)) != null) {
            res.addExtension(new Extension("Java MIDP",ver));
            ver = context.getcVersionAfterPattern("Java/Jbed/",MatchingType.BEGINS, MatchingRegion.REGULAR);
            if (ver != null) res.addExtension(new Extension("Java Jbed",ver));
            ver = context.getcVersionAfterPattern("Configuration/CLDC-",MatchingType.BEGINS, MatchingRegion.BOTH);
            if (ver==null) ver = context.getcVersionAfterPattern("configuration/CLDC-",MatchingType.BEGINS, MatchingRegion.BOTH);
            if (ver != null) res.addExtension(new Extension("Java CLDC",ver));
            ver = context.getcVersionAfterPattern("JavaPlatform/JP-",MatchingType.BEGINS, MatchingRegion.BOTH);
            if (ver != null) res.addExtension(new Extension("Java Platform",ver));

        }
        if (res.browser.description.startsWith("Silk")) {
            if (context.consume("Silk-Accelerated=true",MatchingType.EQUALS, MatchingRegion.REGULAR)) {
                res.addExtension(new Extension("Silk-Accelerated",""));
            }
        }
        if (res.browser.description.startsWith("ELinks") || res.browser.description.startsWith("Lynx") || res.browser.description.startsWith("Links") || res.operatingSystem.family == OSFamily.WINDOWS_MOBILE) {
            String reso = context.getcToken("[0-9]+x[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
            if (reso != null)
                res.addExtension(new Extension("Resolution",reso));
        }
        if (res.operatingSystem.family == OSFamily.WINDOWS_MOBILE) {
            String reso = context.getcToken("[0-9]+x[0-9]+;?", MatchingType.REGEXP, MatchingRegion.BOTH);
            if (reso != null) {
                if (reso.endsWith(";")) reso = reso.substring(0, reso.length()-1);
                res.addExtension(new Extension("Resolution",reso));
            }
        }
        if (res.browser.family == BrowserFamily.IE) {
            if (context.consume("DigExt",MatchingType.EQUALS, MatchingRegion.PARENTHESIS) || context.consume("MSIECrawler",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res.addExtension(new Extension("Offline Save")); // IE downloading for offline access
            }
            if ((ver = context.getcVersionAfterPattern("chromeframe/",MatchingType.BEGINS, MatchingRegion.BOTH)) != null) {
                res.addExtension(new Extension("Chrome Frame",ver));
            }
        }

        if (res.browser.family == BrowserFamily.FIREFOX || res.browser.family == BrowserFamily.OTHER_GECKO) {

            if (res.browser.description.startsWith("Thunderbird")) {
                if ((ver = context.getcVersionAfterPattern("ThunderBrowse/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
                    res.addExtension(new Extension("ThunderBrowse",ver));
                }
            }


            if ((ver = context.getcVersionAfterPattern("Navigator/",  MatchingType.BEGINS, MatchingRegion.BOTH))!=null) {
                res.addExtension(new Extension("Netscape Navigator",ver));
            }
            if (context.consume("pango-text",  MatchingType.EQUALS, MatchingRegion.REGULAR)) {
                res.addExtension(new Extension("pango-text","")); // Font rendering engine (usually on Fedora)
            }
        }

        if ((ver = context.getcVersionAfterPattern("UP.Link/", MatchingType.BEGINS, MatchingRegion.REGULAR, 3)) != null) {
            res.addExtension(new Extension("UP.Link",ver)); // Some WAP gateway
        }
        String[]multi;
        if ((multi = context.getcNextTokens(new Matcher[] {new Matcher("WebWasher", MatchingType.EQUALS),
            new Matcher("[0-9\\.]+", MatchingType.REGEXP)
        },
        MatchingRegion.REGULAR)) != null) {
            res.addExtension(new Extension("WebWasher",multi[1])); // Software proxy for content filtering
        }
        if ((ver = context.getcVersionAfterPattern("Webwasher/", MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
            res.addExtension(new Extension("WebWasher",ver)); // Software proxy for content filtering
        }

    }

    static boolean consumeEntityFromIEAndFirefox(String entity, String ver, UserAgentContext context, UserAgentDetectionResult result) {
        String sep;
        MatchingRegion region;
        if (result.browser.family == BrowserFamily.OTHER_TRIDENT || result.browser.family == BrowserFamily.IE) {
            sep = " ";
            region = MatchingRegion.PARENTHESIS;
        } else {
            sep = "/";
            region = MatchingRegion.REGULAR;
        }
        String regexp = (ver == null) ? entity : (entity+sep+ver);
        return context.ignore(regexp, MatchingType.REGEXP, region);
    }

    static void consumeRandomGarbage(UserAgentContext context, UserAgentDetectionResult result) {
        context.ignore("3gpp-gba", MatchingType.EQUALS, MatchingRegion.REGULAR); // Authentication protocol
        context.ignore("MALC", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); //Multiple Access Line Concentrator
        context.consume("U", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // "Secure" flag


        if (result.operatingSystem.family == OSFamily.WINDOWS_NT) {
            if (result.browser.family == BrowserFamily.IE || result.browser.family == BrowserFamily.OTHER_TRIDENT) {
                context.consume("SLCC1", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Some versionning only MS has an explanation for
                context.consume("SLCC2", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Some versionning only MS has an explanation for
            }
            context.ignore("AskTb", MatchingType.BEGINS, MatchingRegion.BOTH); // Dunno what that is
            context.ignore("BRI/1", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Bing toolbar
            context.ignore("BRI/2", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Bing toolbar
            context.ignore("EasyBits GO v[0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Easybits Skype app
            while (context.consume(".NET4\\.[0-9+][A-Z]?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) ;
            context.ignore("\\+sfgR[0-9a-zA-Z]+(==)?(%3D%3D)?\\+", MatchingType.REGEXP, MatchingRegion.REGULAR); // Haven't got the faintest idea
            context.ignore("\\{[0-9A-F]{8}\\-[0-9A-F]{4}\\-[0-9A-F]{4}\\-[0-9A-F]{4}\\-[0-9A-F]{12}\\}", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Some CLSID or another I guess
        }

        if (result.operatingSystem.family == OSFamily.WINDOWS_NT || result.operatingSystem.family == OSFamily.WINDOWS) {
            while (context.consume(".NET CLR", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) ;
            while (context.consume(".NET Client [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) ;
            context.ignore("HbTools [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Hotbar - kindof adware
        }


        if (result.operatingSystem.family == OSFamily.LINUX ||
                result.operatingSystem.family == OSFamily.UNIX ||
                result.operatingSystem.family == OSFamily.BSD ||
                result.operatingSystem.family == OSFamily.OTHER) {
            context.consume("X11", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // X11 windowing environment
            if (result.operatingSystem.description.equals("SuSE")) {
                // Sometimes...
                context.consume("X11", MatchingType.EQUALS, MatchingRegion.REGULAR); // X11 windowing environment
            }
        }
        if (result.browser.family == BrowserFamily.OTHER_TRIDENT || result.browser.family == BrowserFamily.IE) {
            context.ignore("image_azv", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Dunno
            context.ignore("Tucows", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Dunno
            context.ignore("TOB 6\\.[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Dunno
            {   // Trojan: http://blog.armorize.com/2010/05/browser-helper-objects-infection-with.html and http://www.spambotsecurity.com/forum/viewtopic.php?f=43&t=1579
                context.ignore("SIMBAR=\\{[0-9ABCDEFabcdef\\-]+\\}", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
                context.ignore("SIMBAR Enabled", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                context.ignore("SIMBAR=0", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            }
            context.ignore("WWTClient2", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // World Wide Telescope Client?
            context.ignore("F-6\\.0SP[1-2]-200[0-9][0-9][0-9][0-9][0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Dunno
            while (context.ignore("SU [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)); // Dunno
            context.ignore("tnet.2007feb", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Dunno
            context.ignore("ibrytetoolbar_playbryte", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Dunno
            while (context.ignore("Qwest [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)); // Dunno
            while (context.ignore("Qwest Communications", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)); // Gotta go with corporate installs

            if (context.ignore("system:[0-9]+\\.[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS) // Dunno
                    || context.ignore("patch:[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS) // Dunno
                    || context.ignore("compat/[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS) // Dunno
                    || context.ignore("control/[0-9]\\.[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS) // Dunno
                    || context.ignore("Build/[0-9]+\\.[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS) // Dunno
                    || context.ignore("App/[0-9]+\\.[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS) // Dunno
                    || context.ignore("Service [0-9]\\.[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) // Dunno
                while (context.consume("[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) ;

            context.ignore("XF_mmhpset", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Dunno
            context.ignore("IE0006_ver1", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Dunno
            context.ignore("managedpc", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Dunno
            context.ignore("SVD", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Dunno
            context.ignore("WinNT-PAI [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Trojan http://www.threatexpert.com/report.aspx?md5=72e15bf94e8cb6ea2fc8d0626774ddd2
            context.ignore("VB_juicypalace", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Dunno?
            context.ignore("UGDCFR [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Dunno
            context.ignore("eMusic DLM/4", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // eMusic Download Manager
            if (context.ignore("BO1IE8_v1", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) { // Dunno
                context.ignore("ENUS", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            }
            while (context.ignore("MS-RTC ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)); // NetMeeting
            while (context.ignore("desktopsmiley_[0-9_]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) {
                context.ignore("DS_desktopsmiley", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            }

        } else {
            if (null != context.ignoreNextTokens(new Matcher[] {new Matcher("Service", MatchingType.EQUALS),
                new Matcher("[0-9]\\.[0-9]+", MatchingType.REGEXP)
            },
            MatchingRegion.REGULAR)
            || context.ignore("patch:[0-9]+", MatchingType.REGEXP, MatchingRegion.REGULAR)
            || context.ignore("App/[0-9]+\\.[0-9]+", MatchingType.REGEXP, MatchingRegion.REGULAR)) // WTF ?
            while (context.consume("[0-9]+", MatchingType.REGEXP, MatchingRegion.REGULAR)) ;

            context.ignore("SVD", MatchingType.EQUALS, MatchingRegion.REGULAR); // Dunno
            context.ignore("VB_juicypalace", MatchingType.EQUALS, MatchingRegion.REGULAR); // Dunno?
            context.ignore("UGDCFR/[0-9\\.]+", MatchingType.REGEXP, MatchingRegion.REGULAR); // Dunno
            context.ignoreNextTokens(new Matcher[] {new Matcher("eMusic", MatchingType.EQUALS),
                                         new Matcher("DLM/[0-9\\._]*", MatchingType.REGEXP)
            },
            MatchingRegion.REGULAR); // eMusic Download Manager
        }

        if (result.browser.family == BrowserFamily.OTHER_GECKO || result.browser.family == BrowserFamily.FIREFOX) {
            context.ignore("lolifox/", MatchingType.BEGINS, MatchingRegion.REGULAR); // Some bullshit addon to FF
            context.ignore("tete009 .*SSE[2]?.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Custom FF build http://www1.plala.or.jp/tete009/en-US/software.html
            context.ignore("tete009 .*MMX?.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Custom FF build
            if (context.ignore("compat/[0-9]+", MatchingType.REGEXP, MatchingRegion.REGULAR)) // Dunno
                while (context.consume("[0-9]+", MatchingType.REGEXP, MatchingRegion.REGULAR)) ;
            context.ignore("XF_mmhpset", MatchingType.EQUALS, MatchingRegion.REGULAR); // Dunno
            context.ignore("BT-lookingforgroup", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Dunno
            context.ignore("RTSE/[0-9\\.]+", MatchingType.REGEXP, MatchingRegion.REGULAR); // Dunno
            context.ignore("MultiZilla/", MatchingType.BEGINS, MatchingRegion.REGULAR); // Collection of FF extensions
            context.ignore("FirePHP/", MatchingType.BEGINS, MatchingRegion.REGULAR); // extension for developers
            context.ignore("FireShot/", MatchingType.BEGINS, MatchingRegion.REGULAR); // Screeshot extension for FF
            context.ignore("UGA6PV", MatchingType.BEGINS, MatchingRegion.REGULAR);// This website would suggest this is operated by a human: http://forums.mozfr.org/viewtopic.php?t=66727&p=455964
            //context.ignore("CK-[0-9a-zA-Z\\.\\-_]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);// Dunno what that is, but it looks widespread enough not to be a robot
            if (context.getUA().indexOf("(CK-")>-1)
                context.ignore("CK-[0-9a-zA-Z\\.\\-_]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);// Dunno what that is, but it looks widespread enough not to be a robot
            context.ignoreNextTokens(new Matcher[] {new Matcher("WinNT-PAI", MatchingType.EQUALS),
                                         new Matcher("[\\.0-9]+", MatchingType.REGEXP)
            },
            MatchingRegion.REGULAR); // Trojan http://www.threatexpert.com/report.aspx?md5=72e15bf94e8cb6ea2fc8d0626774ddd2


            if (result.browser.description.startsWith("Thunderbird")) {
                context.consume("Lightning/",  MatchingType.BEGINS, MatchingRegion.REGULAR); // Calendar extension to thunderbird
            }


        } else if (result.browser.description.startsWith("Lynx")) {
            context.consume("textmode", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        }

        context.ignore("WPDesktop", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Wordpress Desktop


        // Crap from operators / ISPs
        context.ignore("Sprint", MatchingType.EQUALS, MatchingRegion.REGULAR);
        context.ignore("Orange [0-9]\\.[0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("Wanadoo [0-9]\\.[0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("NaviWoo[0-9]\\.[0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // WTF?
        context.ignore("XMPP Tiscali Communicator v\\.[0-9]+\\.[0-9]+\\.[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("Total Internet", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("Sky Broadband", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("Rogers Hi-Speed Internet", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("Neostrada TP ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
        if (result.device.deviceType.isMobile()) {
            context.ignore("Orange", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // French operator
            context.ignore("SFR", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // French operator
            context.ignore("bouygues", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // French operator
            context.ignore("Vodafone", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Phone operator
            context.ignore("T-Mobile", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Phone operator
        }



        // Bullshitware
        while (context.ignore("FunWebProducts", MatchingType.REGEXP, MatchingRegion.BOTH)); // Is this malware? Probably.
        while (context.ignore("InfoPath\\.[0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS));
        context.ignore("Zune [0-9.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("OfficeLiveConnector\\.[0-9]\\.[0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("OfficeLivePatch\\.[0-9]\\.[0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("KKman[0-9]\\.[0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("FireDownload/[0-9]+(\\.[0-9]+)+", MatchingType.REGEXP, MatchingRegion.REGULAR);
        if (result.browser.family == BrowserFamily.IE) {
            context.ignore("MS-OC 4.0", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // MS Office Communicator
            context.ignore("Zune [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Zune
        }
        context.ignore("FDM"  , MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // FreeDownloadManager
        context.ignore("Glue/", MatchingType.BEGINS, MatchingRegion.REGULAR); // Plugin to find Books, music, ...
        context.ignore("eSobiSubscriber ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS); // May come from a "offline reading" app or from a legit browser on a PC with the app installed...
        context.ignore("Windows Live Messenger [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("Creative AutoUpdate v[0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // WTF is this doing in a UA???
        while (context.ignore("DS_gamingharbor", MatchingType.EQUALS, MatchingRegion.BOTH));
        while (context.ignore("desktopsmiley(_[0-9]+)+", MatchingType.REGEXP, MatchingRegion.BOTH));
        while (context.ignore("DS_juicyaccess", MatchingType.EQUALS, MatchingRegion.BOTH));
        context.consume("yplus ",MatchingType.BEGINS, MatchingRegion.PARENTHESIS);

        context.ignoreNextTokens(new Matcher[] {new Matcher("[Mm][Ss][Nn] OptimizedIE8", MatchingType.REGEXP),
                                     new Matcher("[A-Z][A-Z][A-Z][A-Z]", MatchingType.REGEXP)
        },
        MatchingRegion.PARENTHESIS); // WTF ?
        context.ignore("iOpus-I-M",MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // iOpus Internet Macros
        context.ignore("AdCentriaIM/",MatchingType.BEGINS, MatchingRegion.REGULAR); // Some king of instant messaging? Couldn't find anything on this


        // BullshitToolbarWare
        while (context.ignore("gmx/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)); // GMX the mail service?
        context.ignore("tb-gmx/", MatchingType.BEGINS, MatchingRegion.BOTH); // GMX the mail service?
        context.ignore("GetMiroToolbar ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS); // Self Explanatory
        context.ignore("GMX/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS); // GMX the mail service?
        context.ignore("QuizulousSearchToolbar [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Self explanatory
        context.ignore("YComp [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Yahoo Companion (useful I guess if you are lonely and in need of a companion). Thanks http://www.webmasterworld.com/forum11/1416.htm

        if (context.ignore("GTB[0-9\\.]+", MatchingType.REGEXP, MatchingRegion.BOTH)) { //Google Toolbar
            context.consume("GTBDFff",MatchingType.EQUALS, MatchingRegion.REGULAR);
        }
        context.ignore("AskTB[0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // WTF?

        context.ignore("Alexa", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Is this really Alxea Toolbar?
        context.ignore("Alexa Toolbar", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("AlexaToolbar/", MatchingType.BEGINS, MatchingRegion.REGULAR);
        context.ignoreNextTokens(new Matcher[] {new Matcher("Alexa", MatchingType.EQUALS),
                                     new Matcher("Toolbar", MatchingType.EQUALS)
        },
        MatchingRegion.REGULAR);

        context.ignore("Hotbar [0-9]+\\.[0-9]\\.[0-9]+\\.[0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("HotbarSearchToolbar [0-9]\\.[0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("Every Toolbar", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("MEGAUPLOAD[ =][0-9]\\.0", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("MEGAUPLOAD [0-9]\\.0", MatchingType.REGEXP, MatchingRegion.REGULAR);
        context.ignore("MEGAUPLOADTOOLBARV2.0", MatchingType.EQUALS, MatchingRegion.REGULAR);
        context.ignore("StumbleUpon/", MatchingType.BEGINS, MatchingRegion.REGULAR); // Why changing the UA? Really?

        if (context.getUA().contains(";MEGAUPLOAD 1.0")) {
            context.consume("1.0", MatchingType.EQUALS, MatchingRegion.REGULAR);
        }
        context.ignore("FBSMTWB", MatchingType.EQUALS, MatchingRegion.BOTH); // Fast Browser Search toolbar
        context.ignore("BLNGBAR", MatchingType.EQUALS, MatchingRegion.BOTH); // Dunno

        context.ignoreNextTokens(new Matcher[] {new Matcher("MEGAUPLOAD", MatchingType.EQUALS),
                                     new Matcher("[12]\\.0(\\.)?", MatchingType.REGEXP)
        },
        MatchingRegion.REGULAR);

        context.ignore("AOLBuild [0-9]+\\.[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("SearchToolbar [0-9]\\.[0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("AskTbWBR/[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("MSN Optimized", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("Dealio Toolbar [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignoreNextTokens(new Matcher[] {new Matcher("Dealio", MatchingType.EQUALS),
                                     new Matcher("Toolbar", MatchingType.EQUALS),
                                     new Matcher("[0-9\\.]+", MatchingType.REGEXP)
        },
        MatchingRegion.REGULAR);

        context.ignoreNextTokens(new Matcher[] {new Matcher("Creative", MatchingType.EQUALS),
                                     new Matcher("ZENcast", MatchingType.EQUALS),
                                     new Matcher("v[0-9\\.]+", MatchingType.REGEXP)
        },
        MatchingRegion.REGULAR);
        context.ignore("Creative ZENcast v[0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("PBSTB [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Dunno what that is. I assume TB == Toolbar
        context.ignore("YTB730", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Dunno what that is. I assume TB == Toolbar
        context.ignore("BarreMagique", MatchingType.EQUALS, MatchingRegion.BOTH); // Web Radio
        context.ignore("SuperSearchSearchToolbar [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);  // Dunno.
        context.ignoreNextTokens(new Matcher[] {new Matcher("VRE", MatchingType.EQUALS),new Matcher("Toolbar", MatchingType.EQUALS),
                                     new Matcher("[0-9\\.]+", MatchingType.REGEXP)
        },
        MatchingRegion.REGULAR);


        // Mail.ru Agent - Instant Messenger / VoIP / Malware ?
        if (context.ignore("MRA [0-9]\\.[0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS) ||
        null != context.ignoreNextTokens(new Matcher[] {new Matcher("MRA", MatchingType.EQUALS),
                 new Matcher("[0-9]\\.[0-9]", MatchingType.REGEXP)
        },
        MatchingRegion.REGULAR)) {
            context.consume("build [0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        }

        while (context.ignore("Ant.com Toolbar [0-9](\\.[0-9]+)+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS) ||
        null != context.ignoreNextTokens(new Matcher[] {new Matcher("Ant.com", MatchingType.EQUALS),
                 new Matcher("Toolbar", MatchingType.EQUALS),
                 new Matcher("[0-9](\\.[0-9]+)+", MatchingType.REGEXP)
        },
        MatchingRegion.REGULAR)) ;
        context.ignore("ImageShackToolbar/[0-9\\.]+", MatchingType.REGEXP, MatchingRegion.REGULAR);
        context.ignore("ImageShack Toolbar [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);



        // Plugins
        context.ignore(".*Embedded.*http://(www\\.)?bsalsa\\.com/.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("MathPlayer [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("FirePHP/4Chrome", MatchingType.EQUALS, MatchingRegion.REGULAR);
        if (!context.ignore("WEB.DE", MatchingType.EQUALS, MatchingRegion.REGULAR))
            context.ignore("Web.de", MatchingType.EQUALS, MatchingRegion.REGULAR);
        context.ignore("webde/[0-9\\.]+", MatchingType.REGEXP, MatchingRegion.BOTH);
        context.ignore("tb-webde/[0-9\\.]+", MatchingType.REGEXP, MatchingRegion.BOTH);


        context.ignore("MSSDMC[0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Some download manager
        while(context.ignore("SRS_IT_[0-9A-F]{22}", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)); // Smart Repair Solutions ?
        context.ignoreNextTokens(new Matcher[] {new Matcher("WebMoney", MatchingType.EQUALS),
                                     new Matcher("Advisor", MatchingType.EQUALS)
        }, MatchingRegion.REGULAR);
        context.ignore("byond_4.0", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Game thingy
        if (context.ignore("AutoPager/[0-9\\.]+", MatchingType.REGEXP, MatchingRegion.REGULAR)) {
            context.consume("http://www.teesoft.info/", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        }

        // Security / Viruses
        context.ignore("CyberSafe-IWA-Enable", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // TrustBroker CyberSafe
        context.ignore("AntivirXP08", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Is this a virus? Cooool.
        if (result.operatingSystem.family == OSFamily.WINDOWS_NT) {
            context.ignore("AskTbARS/", MatchingType.BEGINS, MatchingRegion.BOTH); // Some remote working crap
        }
        while (context.ignore("Foxy/1", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)); // *Maybe* some kind of proxy
        context.ignore("\\[eburo v[0-9].[0-9]\\]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("WinNT-EVI [0-9][0-9]\\.[0-9][0-9]\\.[1-2]0[0-9][0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Antivir
        context.ignore("WinTSI [0-9][0-9]\\.[0-9][0-9]\\.[1-2]0[0-9][0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Personal Security Virus
        context.ignore("360SE", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // 360 Security Explorer https://kb.bluecoat.com/index?page=content&id=KB4979&actp=RSS
        context.ignore("ShopperReports [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Seems to be some crapware/virus proposing "good deals"
        context.ignore("Edutice/", MatchingType.BEGINS, MatchingRegion.REGULAR); // French device locking software for education
        while (context.ignore("hotvideobar_[0-9_]+", MatchingType.REGEXP, MatchingRegion.BOTH)); // Malware https://forums.malwarebytes.org/index.php?/topic/26285-hotvideobar/
        while (context.ignore("VB_gameztar", MatchingType.REGEXP, MatchingRegion.BOTH)); // Malware ? GamezTar is.

        // DL manager
        context.ignore("QQDownload [0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);

        // Dev tools
        context.ignore("Google Page Speed Insights", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("Google Page Speed", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);


        // Unknown
        while (consumeEntityFromIEAndFirefox("UGES[VULMYF]?", "[0-9\\.]+", context, result)); // Dunno
        consumeEntityFromIEAndFirefox("LUDI2", null, context, result); // Dunno

        context.ignore("YB/", MatchingType.BEGINS, MatchingRegion.BOTH);

        while (context.ignore("AtHome([A-Z][A-Z])?[0-9][0-9][0-9][0-9]?(SI)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS));
        while (context.ignore("QS [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS));
        context.ignore("BTRS[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("Zango [\\.0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("LBEXG/[\\.0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore(".NAP [\\.0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("ZangoToolbar [\\.0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("APC", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("LEN2", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("Hemmit", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("N", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("QwestIE8(x64)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("MAAU", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("CIBA", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("NET_mmhpset", MatchingType.EQUALS, MatchingRegion.BOTH);
        context.ignore("MDDS", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("MA[SE]M(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("MALN(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("MAGW(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("MAPB", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("SKY14", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("KPN", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("SHC", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("Alcohol Search", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("MSOCD", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        if (result.browser.family == BrowserFamily.FIREFOX) {
            context.ignore("YFF[0-9]+", MatchingType.REGEXP, MatchingRegion.REGULAR);
        }


        if (result.browser.family == BrowserFamily.IE || result.browser.family == BrowserFamily.OTHER_TRIDENT) {
            // TODO: http://www.whatismybrowser.com/developers/unknown-user-agent-fragments
            context.ignore("C[PM]DTDF", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
            context.ignore("CPNTDF", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.ignore("HPMTDF", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.ignore("MDDS", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.ignore("MAAU", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.ignore("MA[SLT]M(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
            context.ignore("MIDP", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.ignore("MAAU", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.ignore("MATP", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.ignore("MAPT", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.ignore("MANM", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.ignore("MALNJS", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.ignore("MAFS", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.ignore("MAMD", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.ignore("MAMI", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.ignore("MAGWJS", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.ignore("MATPJS", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.ignore("MANMJS", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.ignore("MAFSJS", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.ignore("MAMIJS", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);

            // Other stuff
            while (context.ignore("IEMB3", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)); // Unknown, maybe an ActiveX that is mostly used for nefarious purposes according to http://forums.3drealms.com/vb/showthread.php?t=32908
            context.ignore("ADOK", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Unknown
            context.ignore("LIZOK", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Unknown
            context.ignore("GIS IE 6.0 Build [0-9]{8}", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        }

        if (context.contains("Le Grand Lyon", MatchingType.EQUALS, MatchingRegion.PARENTHESIS) &&
                context.contains("Tic1_[A-Z]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS) &&
                context.contains("Tic2_[0-9a-f]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) {
            context.ignore("Le Grand Lyon", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.ignore("Tic1_[A-Z]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
            context.ignore("Tic2_[0-9a-f]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        }


        // Misc
        if (context.ignore("UPS-Corporate", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) { // WTF were they thinking?
            context.consume("UPS-Corporate", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        }
        if (context.getUA().contains("gzip(gfe)")) {
            context.consume("gfe", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume(",gzip", MatchingType.EQUALS, MatchingRegion.REGULAR);
        }
    }

    /**
     * Parse a user-agent string
     *
     * @param ua The user agent string as sent by the browser
     * @return   The result of the detection
     */
    public UserAgentDetectionResult parseUserAgent(String ua) {
        UserAgentContext context = new UserAgentContext(ua);


        UserAgentDetectionResult res = getBot(context);
        if (res!=null) return res.wrapUp(context);
        res = getLibraries(context);
        if (res!=null) return res.wrapUp(context);


        res = new UserAgentDetectionResult();
        res.locale = getLocale(context);

        res.operatingSystem = getOS(context);
        //res.operatingSystem = new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"browser", "browser");

        res.browser = getBrowser(context, res.operatingSystem);

        res.device = getDevice(context,res.browser,res.operatingSystem);

        addExtensions(context, res);

        consumeRandomGarbage(context, res);

        return res.wrapUp(context);
    }

    public static void test() {
        UserAgentContext.test();
    }
}