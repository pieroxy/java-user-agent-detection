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

    static void consumeRegularWindowsGarbage(UserAgentContext context) {
        context.consume("Windows", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.consume("Windows", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
        context.consume("U", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.consume("rv:[0-9]\\.[0-9]\\.[0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
    }

    static void consumeWebKitBullshit(UserAgentContext context) {
        UserAgentDetectionHelper.consumeMozilla(context);
        if (!context.consume("AppleWebKit/", MatchingType.BEGINS, MatchingRegion.REGULAR))
            context.consume("AppleWebkit/", MatchingType.BEGINS, MatchingRegion.REGULAR);
        context.consume("Safari/", MatchingType.BEGINS, MatchingRegion.REGULAR);
        context.consume("Mobile", MatchingType.EQUALS, MatchingRegion.REGULAR);
        context.consume("KHTML, [lL]ike Gecko", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
    }


    static boolean isKindle(UserAgentContext context, boolean expectConsumed) {
        MatchingRegion region = (expectConsumed)?MatchingRegion.CONSUMED:MatchingRegion.PARENTHESIS;
        return context.consume("KFTT", MatchingType.BEGINS, region) ||
               context.consume("KFOTE", MatchingType.BEGINS, region) ||
               context.consume("KFOT", MatchingType.BEGINS, region) ||
               context.consume("KFJWI", MatchingType.BEGINS, region) ||
               context.consume("KFTHWI", MatchingType.BEGINS, region);
    }

    static void consumeUbuntuVersion(UserAgentContext context) {
        context.consume("hardy", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.consume("gutsy", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.consume("maverick", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.consume("lucid", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.consume("intrepid", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.consume("karmic", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.consume("jaunty", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.consume("[0-9\\.]+-[0-9]ubuntu[0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.consume("Ubuntu package [0-9\\.]+(-[0-9]ubuntu[0-9])?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
    }

    static OS getOS(UserAgentContext context) {
        String userAgent = context.getUA();
        OS res = null;
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
                res.appendToVersion(" Series60 " + ver);
            } else {
                ver=context.getcVersionAfterPattern("S60/", MatchingType.BEGINS,MatchingRegion.BOTH);
                if (ver != null) res.appendToVersion(" Series60 " + ver);
            }
            if (context.consume("Symbian OS", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                context.consume("[0-9]{3}[0-9]?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
            }
            res.setVersion(res.getVersion().trim());
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
            if (ver != null && ver.length()>res.getVersion().length()) // SonyEricsson UAs include the version twice. Get the most precise one.
                res.setVersion(ver);
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
                    res.appendToVersion(" SP2");
                    sp2 = true;
                }
                if ((ver=context.getcVersionAfterPattern("Media Center PC ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                    if (ver.equals("2.7") || ver.equals("2.8"))
                        res.appendToVersion(" Media Center 2004");
                    else if (ver.equals("3.0") || ver.equals("3.1") || ver.equals("4.0")) {
                        res.appendToVersion(" Media Center 2005");
                        if (ver.equals("3.1")) res.appendToVersion(" (update rollup 1)");
                        if (ver.equals("4.0")) res.appendToVersion(" (update rollup 2)");
                        if (!sp2) {
                            res.appendToVersion(" SP2");
                            sp2 = true;
                        }
                    } else {
                        try {
                            if (Float.parseFloat(ver) < 2.7)
                                res.appendToVersion(" Media Center 2002");
                        } catch (Exception e) {
                            res.appendToVersion(" Media Center " + ver);
                        }
                    }
                    context.consume("Media Center PC ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS); // Sometimes present more than once
                }
            } else if (context.consume("Windows NT 6.0", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                context.consume("SV1", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","Vista");
                if ((ver=context.getcVersionAfterPattern("Media Center PC ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                    if (ver.equals("5.0"))
                        res.appendToVersion(" Media Center");
                    else if (ver.equals("5.1"))
                        res.appendToVersion(" Media Center TV Pack");
                    else
                        res.appendToVersion(" Media Center " + ver);
                    context.consume("Media Center PC ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS); // Sometimes present more than once
                }
            } else if (context.contains("Windows NT   6.0", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) &&
                       context.contains("Java/", MatchingType.BEGINS, MatchingRegion.REGULAR) &&
                       context.contains("unknown", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                context.consume("Windows NT   6.0", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
                context.consume("unknown", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","Vista");
            } else if (context.consume("Windows NT 6.1", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                context.consume("SV1", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","7");
                if ((ver=context.getcVersionAfterPattern("Media Center PC ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                    if (ver.equals("6.0"))
                        res.appendToVersion(" Media Center");
                    else
                        res.appendToVersion(" Media Center " + ver);
                    context.consume("Media Center PC ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS); // Sometimes present more than once
                }
            } else if (context.consume("Windows NT 6.2", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","8");
                if (context.consume("ARM", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                    res.appendToVersion(" RT");
                }
                context.consume("Touch", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            } else if (context.consume("Windows NT 6.3", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","8.1");
            } else if (context.consume("Windows NT 6.4", MatchingType.EQUALS, MatchingRegion.PARENTHESIS) ||
                       context.consume("Windows NT 10.0", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","10");
            } else if (context.consume("Windows NT 5.0", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","2000");
                if (context.contains("Windows NT 5.01", MatchingType.BEGINS, MatchingRegion.CONSUMED)) res.appendToVersion(" SP1");
            } else if (context.consume("Windows NT 5.2", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","2003 or XP x64 Edition");
                context.consume("SV1", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            } else if (context.consume("Windows NT( )?4.0", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","NT4");
            } else if (context.consume("Windows NT 3.51", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","NT 3.51");
            } else if (context.consume("Windows NT", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Win","NT");
            } else
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"WinNT?","WinNT?");
            /*if ((pos=userAgent.indexOf("Tablet PC"))>-1 && userAgent.indexOf("Touch")>-1)
                res.appendToVersion(" Tablet PC " + getVersionNumber(userAgent, pos+9));*/
        } else if (context.consume("Windows XP 5.1", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","XP");
        } else if (context.consume("Windows XP", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_NT,"Windows","XP");
            if (context.consume("SV1", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res.appendToVersion(" SP2");
            }
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
            } else if (context.getcNextTokens(new Matcher[] {new Matcher("Windows", MatchingType.EQUALS),
                new Matcher("Mobile", MatchingType.EQUALS),
                new Matcher("6.5", MatchingType.EQUALS),
                new Matcher("Standard",MatchingType.BEGINS)
            }, MatchingRegion.REGULAR) != null) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_MOBILE,"Windows","Mobile (6.5)");
                context.consume("Windows CE",MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            }
            else if (context.consume("Windows CE",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_MOBILE,"Windows","CE");
            } else if (context.getcNextTokens(new Matcher[] {new Matcher("Windows Mobile", MatchingType.EQUALS),
                new Matcher("WCE",MatchingType.EQUALS)
            }, MatchingRegion.PARENTHESIS) != null) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_MOBILE,"Windows","Mobile (CE)");
            }
            else if (context.getcNextTokens(new Matcher[] {new Matcher("Windows Mobile", MatchingType.EQUALS),
                     new Matcher("PPC",MatchingType.EQUALS)
            }, MatchingRegion.PARENTHESIS) != null) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_MOBILE,"Windows","Mobile (Pocket PC)");
            }
            else if ((ver = context.getcVersionAfterPattern("Windows Mobile/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_MOBILE,"Windows","Mobile ("+ver+")");
            } else if ((ver = context.getcVersionAfterPattern("Windows Mobile", MatchingType.EQUALS, MatchingRegion.PARENTHESIS))!=null) {
                res = new OS(Brand.MICROSOFT,OSFamily.WINDOWS_MOBILE,"Windows","Mobile");
            } else if (context.consume("Windows 3.11",MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
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

            if (res.getFamily() == OSFamily.WINDOWS_MOBILE) {
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
                    res.appendToVersion(" (CyanogenMod "+ver+")");
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
            res = new OS(Brand.UNKNOWN,OSFamily.LINUX,"CentOS", ver);
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
                    consumeUbuntuVersion(context);
                } else if ((ver = context.getcVersionAfterPattern("Ubuntu-feisty", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) != null) {
                    med = "Ubuntu";
                    detail = "7.04";
                    consumeUbuntuVersion(context);
                } else if ((ver = context.getcVersionAfterPattern("Ubuntu-edgy", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) != null) {
                    med = "Ubuntu";
                    detail = "6.10";
                    consumeUbuntuVersion(context);
                } else if ((mt = context.getcNextTokens(new Matcher[] {new Matcher("Kubuntu", MatchingType.EQUALS),
                    new Matcher("[\\.0-9]+",MatchingType.REGEXP)
                }, MatchingRegion.REGULAR)) != null ||
                (ver = context.getcVersionAfterPattern("Kubuntu package ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) != null ||
                (ver = context.getcVersionAfterPattern("Kubuntu/", MatchingType.BEGINS, MatchingRegion.REGULAR)) != null ||
                context.consume("Kubuntu", MatchingType.EQUALS, MatchingRegion.BOTH)) {
                    if (mt != null) ver = mt[1];
                    if (ver == null) ver = "";
                    med = "Ubuntu";
                    detail = ("Kubuntu " + ver).trim();
                    context.consume("Dapper", MatchingType.EQUALS, MatchingRegion.REGULAR);
                    context.consume("Debian", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                    consumeUbuntuVersion(context);
                }
                else if (context.consume("karmic", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                    med = "Ubuntu";
                    detail = "9.10";
                    context.getcNextTokens(new Matcher[] {new Matcher("Ultimate", MatchingType.EQUALS),
                                               new Matcher("Edition/",MatchingType.BEGINS)
                    }, MatchingRegion.REGULAR);
                } else if ((mt = context.getcNextTokens(new Matcher[] {new Matcher("Fedora", MatchingType.EQUALS),
                    new Matcher("Core",MatchingType.EQUALS),
                    new Matcher("[0-9]+;",MatchingType.REGEXP)
                }, MatchingRegion.REGULAR)) != null) {
                    med = "Fedora Core";
                    detail = mt[2];
                    if (detail.endsWith(";")) detail = detail.substring(0, detail.length()-1);
                }
                else if ((ver = context.getcVersionAfterPattern("Fedora", MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                    med = "Fedora"; // Used to get the version through ver but it looks like it's the version of the browser, not Fedora's
                    detail = "";
                } else if (context.consume("Fedora", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                    med = "Fedora";
                    detail = "";
                } else if ((mt = context.getcNextTokens(new Matcher[] {new Matcher("Red", MatchingType.EQUALS),
                    new Matcher("Hat/[0-9\\.el\\-]+",MatchingType.REGEXP)
                }, MatchingRegion.REGULAR)) != null) {
                    med = "Red Hat";
                    detail = mt[1].substring(mt[1].indexOf("/")+1);
                }
                else if ((ver = context.getcVersionAfterPattern("openSUSE/", MatchingType.BEGINS, MatchingRegion.REGULAR)) != null) {
                    med = "openSuSE";
                    detail = ver;
                } else if ((ver = context.getcVersionAfterPattern("Linux Mint ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) != null) {
                    med = "Mint";
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
                    consumeUbuntuVersion(context);
                    med = "Ubuntu";
                    detail = "";
                }
                res = new OS(Brand.UNKNOWN,OSFamily.LINUX,med,detail);
            }
        } else if (context.consume("CentOS", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res = new OS(Brand.UNKNOWN,OSFamily.LINUX,"CentOS","");
        } else if ((ver = context.getcVersionAfterPattern("GNU Fedora fc ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) != null) {
            res = new OS(Brand.UNKNOWN,OSFamily.LINUX,"Linux","Fedora " + ver);
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
        } else if ((ver=context.getcToken("BB[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) != null) {
            context.consume("Touch", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            res = new OS(Brand.RIM, OSFamily.BBOS, "BB OS", ver.substring(2));
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
            if (context.consume("Gentoo/", MatchingType.BEGINS, MatchingRegion.BOTH) ||
                    context.consume("Gentoo", MatchingType.EQUALS, MatchingRegion.BOTH)) {
                res = new OS(Brand.UNKNOWN,OSFamily.LINUX,"Gentoo","");
            } else {
                res = new OS(Brand.UNKNOWN,OSFamily.UNIX,"Unix-like","X11 capable");
                context.consume("I", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            }
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

        if (res.getFamily() == OSFamily.WINDOWS_NT) {
            context.consume("Windows", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        }
        if (res.getFamily() == OSFamily.MACOS || res.getFamily() == OSFamily.MACOSX) {
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

    static RenderingEngine getKHTMLVersion(UserAgentContext context) {
        try {
            String ver = context.getcVersionAfterPattern("KHTML/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            if (ver != null) return new RenderingEngine(Brand.OPENSOURCE_COMMUNITY, RenderingEngineFamily.KHTML, ver, 2);
            ver = context.getcVersionAfterPattern("KHTML/", MatchingType.BEGINS, MatchingRegion.CONSUMED);
            if (ver != null) return new RenderingEngine(Brand.OPENSOURCE_COMMUNITY, RenderingEngineFamily.KHTML, ver, 2);
            ver = context.getcVersionAfterPattern("Konqueror/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            if (ver != null) return new RenderingEngine(Brand.OPENSOURCE_COMMUNITY, RenderingEngineFamily.KHTML, "for Konqueror " + ver, 2);
            ver = context.getcVersionAfterPattern("Konqueror/", MatchingType.BEGINS, MatchingRegion.CONSUMED);
            if (ver != null) return new RenderingEngine(Brand.OPENSOURCE_COMMUNITY, RenderingEngineFamily.KHTML, "for Konqueror " + ver, 2);
            return RenderingEngine.getUnknown();
        } finally {
        }
    }

    static RenderingEngine getTridentVersion(UserAgentContext context, String ieWithVersion) {
        String tver = context.getcVersionAfterPattern("Trident/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
        if (tver != null) return new RenderingEngine(Brand.MICROSOFT, RenderingEngineFamily.TRIDENT, tver, 2);
        tver = context.getcVersionAfterPattern("Trident ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
        if (tver != null) return new RenderingEngine(Brand.MICROSOFT, RenderingEngineFamily.TRIDENT, tver, 2);
        return new RenderingEngine(Brand.MICROSOFT, RenderingEngineFamily.TRIDENT, "for IE " + ieWithVersion, 2);
    }

    static RenderingEngine getPrestoVersion(UserAgentContext context, String matched) {
        String ver;
        if ((ver=context.getcVersionAfterPattern("Presto/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            return new RenderingEngine(Brand.OPERA, RenderingEngineFamily.PRESTO, ver, 2);
        }
        if (matched != null) {
            return new RenderingEngine(Brand.OPERA, RenderingEngineFamily.PRESTO, "Opera "+matched, 2);
        }
        return RenderingEngine.getUnknown();
    }

    static RenderingEngine getWebkitVersion(UserAgentContext context) {
        return getWebkitVersion(context, null, false, false);
    }
    static RenderingEngine getWebkitVersion(UserAgentContext context, String chromeVersion, boolean couldBeBlink, boolean isBlink) {
        try {
            Brand brand = Brand.APPLE;
            RenderingEngineFamily refam = RenderingEngineFamily.WEBKIT;
            // Blink
            String ver = chromeVersion;

            if (couldBeBlink && !isBlink) {
                if (ver == null)
                    ver = context.getcVersionAfterPattern("Chrome/", MatchingType.BEGINS, MatchingRegion.REGULAR);
                if (ver != null && ver.indexOf(".")>-1) {
                    try {
                        int v = Integer.parseInt(ver.substring(0, ver.indexOf(".")));
                        isBlink = v > 27; // See https://en.wikipedia.org/wiki/Blink_(web_engine)
                    } catch (NumberFormatException e) {
                        // Meh...
                    }
                }
            }

            if (isBlink) {
                brand = Brand.GOOGLE;
                refam = RenderingEngineFamily.BLINK;
            }

            // Webkit
            ver = context.getcVersionAfterPattern("AppleWebKit/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            if (ver != null) return new RenderingEngine(brand, refam, ver, 2);
            ver = context.getcVersionAfterPattern("Safari/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            if (ver != null) return new RenderingEngine(brand, refam, ver, 2);
            ver = context.getcVersionAfterPattern("KHTML/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            if (ver != null) return new RenderingEngine(brand, refam, ver, 2);
            return new RenderingEngine(brand, refam);
        } finally {
            consumeWebKitBullshit(context);
        }
    }

    static Map<String, GeckoSpinoff> geckoSpinOffs = new HashMap<String, GeckoSpinoff>();
    static {
        geckoSpinOffs.put("Chimera", new GeckoSpinoff());
        geckoSpinOffs.put("Iceweasel", new GeckoSpinoff());
        geckoSpinOffs.put("IceCat", new GeckoSpinoff());
        geckoSpinOffs.put("Firebird", new GeckoSpinoff());
        geckoSpinOffs.put("Conkeror", new GeckoSpinoff());
        geckoSpinOffs.put("conkeror", new GeckoSpinoff("Conkeror"));
        geckoSpinOffs.put("Kazehakase", new GeckoSpinoff());
        geckoSpinOffs.put("Thunderbird", new GeckoSpinoff());
        geckoSpinOffs.put("PaleMoon", new GeckoSpinoff());
        geckoSpinOffs.put("Phoenix", new GeckoSpinoff());
        geckoSpinOffs.put("K-Meleon", new GeckoSpinoff());
        geckoSpinOffs.put("Galeon", new GeckoSpinoff());
        geckoSpinOffs.put("Epiphany", new GeckoSpinoff());
        geckoSpinOffs.put("Flock", new GeckoSpinoff());
        geckoSpinOffs.put("Waterfox", new GeckoSpinoff());
        geckoSpinOffs.put("IceDragon", new GeckoSpinoff());
        geckoSpinOffs.put("SeaMonkey", new GeckoSpinoff(null, new String[] {"Lightning/"}));
        geckoSpinOffs.put("Camino", new GeckoSpinoff(null, new String[] {"MultiLang"}));
        geckoSpinOffs.put("Iceape", new GeckoSpinoff("SeaMonkey (Debian Iceape)", new String[] {"like Seamonkey/", "Firefox/"})); // http://en.wikipedia.org/wiki/Mozilla_Corporation_software_rebranded_by_the_Debian_project
        geckoSpinOffs.put("webaroo", new GeckoSpinoff("Webaroo"));
        geckoSpinOffs.put("Lunascape", new GeckoSpinoff(Brand.LUNASCAPE));
        geckoSpinOffs.put("Netscape", new GeckoSpinoff());
        geckoSpinOffs.put("Netscape6", new GeckoSpinoff("Netscape", new String[] {"m18"}));
    }

    static Browser getGecko(UserAgentContext context, String ver, OS os) {
        if (ver == null) ver = "";
        if (ver.length() > 8) ver = ver.substring(0,8);
        String gv = context.getcVersionAfterPattern("rv:", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
        if (gv == null) gv = ver;
        RenderingEngine re = new RenderingEngine(Brand.MOZILLA, RenderingEngineFamily.GECKO, gv, 2);
        Browser res = new Browser(Brand.MOZILLA, BrowserFamily.OTHER_GECKO,"Gecko-based",re);
        boolean found = false;
        for (Map.Entry<String, GeckoSpinoff> so : geckoSpinOffs.entrySet()) {
            if ((ver = context.getcVersionAfterPattern(so.getKey() + "/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
                res.setFullVersionOneShot(ver, 2);
                res.setDescription(so.getValue().getName()==null?so.getKey():so.getValue().getName());
                if (so.getValue().getBrand() != null) res.setVendor(so.getValue().getBrand());
                context.consume("like Firefox", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
                context.consume("Mozilla",  MatchingType.EQUALS, MatchingRegion.REGULAR);
                context.consume("Firefox/",  MatchingType.BEGINS, MatchingRegion.REGULAR);
                for (String tr : so.getValue().getToRemove())
                    context.consume(tr,  MatchingType.BEGINS, MatchingRegion.BOTH);
                found = true;
                break;
            }
        }

        if (found) {
        } else if (os.getFamily() == OSFamily.WINDOWS &&
                   os.getVersion().equals("98") &&
                   context.contains("N",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS) &&
                   context.contains("m18",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res.setDescription("K-Meleon");
            context.consume("N",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume("m18",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        } else if ((ver = context.getcVersionAfterPattern("Seamonkey-",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res.setFullVersionOneShot(ver, 2);
            res.setDescription("SeaMonkey");
        } else if ((ver = context.getcVersionAfterPattern("GranParadiso/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res.setFamily(BrowserFamily.FIREFOX);
            res.setDescription("Firefox");
            res.setFullVersionOneShot(ver, 2);
            res.fullVersion += " beta - GranParadiso";
            context.consume("Firefox",MatchingType.BEGINS, MatchingRegion.REGULAR);
        } else if (context.consume("AvantBrowser/Tri-Core", MatchingType.EQUALS, MatchingRegion.REGULAR) ||
                   context.consume("Avant TriCore", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res.setVendor(Brand.AVANT);
            res.setDescription("Avant Browser");
            context.consume("Firefox/", MatchingType.BEGINS, MatchingRegion.REGULAR);
        } else if ((ver = context.getcVersionAfterPattern("Firefox/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            context.consume("Fennec/",MatchingType.BEGINS, MatchingRegion.REGULAR); // This is FF for Android, but we already have the OS to tell us that.
            res.setFullVersionOneShot(ver, 2);
            res.setDescription("Firefox");
            res.setFamily(BrowserFamily.FIREFOX);
            if (ver.startsWith("2.") || ver.startsWith("3."))
                context.consume("ffco7", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume("pigfoot",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            UserAgentDetectionHelper.consumeMozilla(context);
        } else if ((ver = context.getcVersionAfterPattern("Namoroka/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null ||
                   (ver = context.getcVersionAfterPattern("Shiretoko/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res.setFamily(BrowserFamily.FIREFOX);
            res.setFullVersionOneShot(ver, 2);
            res.setDescription("Firefox");
        } else if ((ver = context.getcVersionAfterPattern("SWB/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res.setVendor(Brand.HP);
            res.setDescription("Secure Web Browser");
            if (ver.charAt(0) == 'V') ver = ver.substring(1);
            res.setFullVersionOneShot(ver, 2);
        } else if ((ver = context.getcVersionAfterPattern("Minefield/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res.setFamily(BrowserFamily.FIREFOX);
            res.setFullVersionOneShot(ver, 2);
            res.setDescription("Firefox");
            res.fullVersion+=" nightly build";
        } else if ((ver = context.getcVersionAfterPattern("BonEcho/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res.setFullVersionOneShot(ver, 2);
            res.setDescription("Firefox");
            res.setFamily(BrowserFamily.FIREFOX);
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
            res = new Browser(Brand.OPERA, BrowserFamily.OPERA,"Opera Mini",getPrestoVersion(context, mono), mono + v);
        } else if ((multi = context.getcNextTokens(new Matcher[] {new Matcher("Opera", MatchingType.EQUALS),
            new Matcher("^[0-9\\.]+$", MatchingType.REGEXP)
        },
        MatchingRegion.REGULAR)) != null) {
            res = new Browser(Brand.OPERA, BrowserFamily.OPERA,"Opera",getPrestoVersion(context, multi[1]), getOperaVersion(context,multi[1]));
            if (context.consume("Bork-edition", MatchingType.EQUALS, MatchingRegion.REGULAR)) {
                res.fullVersion += " Bork edition";
            }
            context.consume("MSIE 6.0", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.consume("MSIE 5\\.[05]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        }
        return res;
    }

    static float tryParseVersionNumber(String s) {
        try {
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
        } catch (Exception e) {
            return -1;
        }
    }

    static void setInternetExplorerWebview(UserAgentContext context, Browser b) {
        // https://msdn.microsoft.com/fr-fr/library/hh869301(v=vs.85).aspx
        if (context.consume("MSAppHost/",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
            b.setInWebView(true);
        }
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

            if ((vertr=context.getcVersionAfterPattern("Trident/",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null ||
                    (vertr=context.getcVersionAfterPattern("Trident ",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                float trver = tryParseVersionNumber(vertr);

                res = new Browser(Brand.MICROSOFT,BrowserFamily.IE,"IE",new RenderingEngine(Brand.MICROSOFT, RenderingEngineFamily.TRIDENT, trver, 2), verie);

                if (trver == 4.0 && iever < 8) {
                    res.setDescription("IE 8 in compatibility mode " + res.getDescription() + verie);
                    iever=8;
                } else if (trver == 5.0 && iever < 9) {
                    res.setDescription("IE 9 in compatibility mode " + res.getDescription() + verie);
                } else if (trver == 6.0 && iever < 10) {
                    res.setDescription("IE 10 in compatibility mode " + res.getDescription() + verie);
                }
            } else {
                res = new Browser(Brand.MICROSOFT,BrowserFamily.IE,"IE",new RenderingEngine(Brand.MICROSOFT, RenderingEngineFamily.TRIDENT, "for IE " + StringUtils.format(iever), 2), verie);
            }

            if (iever >= 10) {
                setInternetExplorerWebview(context, res);
            }

            if (possibleVersions.indexOf(String.valueOf((int)Math.floor(iever))+",")==-1) res = null;

            if (res != null) {
                // Sometimes more than one of these is present... Dunno why.
                if (context.consume("Deepnet Explorer", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                    res.setFamily(BrowserFamily.OTHER_TRIDENT);
                    res.setDescription("Deepnet Explorer");
                }
                if (context.consume("SlimBrowser", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                    res.setFamily(BrowserFamily.OTHER_TRIDENT);
                    res.setDescription("SlimBrowser");
                }
                if (context.consume("Avant Browser", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                    res.setFamily(BrowserFamily.OTHER_TRIDENT);
                    res.setVendor(Brand.AVANT);
                    res.setDescription("Avant Browser");
                    while (context.consume("Avant Browser", MatchingType.BEGINS, MatchingRegion.PARENTHESIS));
                }
                if (context.consume("TheWorld", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                    res.setFamily(BrowserFamily.OTHER_TRIDENT);
                    res.setVendor(Brand.PHOENIX);
                    res.setDescription("The World");
                    while (context.consume("TheWorld", MatchingType.EQUALS, MatchingRegion.PARENTHESIS));
                }
                if ((ver=context.getcVersionAfterPattern("Crazy Browser ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                    res.setFamily(BrowserFamily.OTHER_TRIDENT);
                    res.setDescription("Crazy Browser");
                    res.setFullVersionOneShot(ver, 2);
                }
                if ((ver=context.getcVersionAfterPattern("Lunascape ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                    res.setFamily(BrowserFamily.OTHER_TRIDENT);
                    res.setVendor(Brand.LUNASCAPE);
                    res.setDescription("Lunascape");
                    res.setFullVersionOneShot(ver, 2);
                }
                if ((ver=context.getcVersionAfterPattern("America Online Browser ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                    res.setFamily(BrowserFamily.OTHER_TRIDENT);
                    res.setDescription("AOL Browser");
                    res.setFullVersionOneShot(ver, 2);
                    context.consume("rev[0-9]\\.[0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
                }
                if (context.consume("MyIE2", MatchingType.EQUALS, MatchingRegion.PARENTHESIS) || context.consume("Maxthon", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                    res.setFamily(BrowserFamily.OTHER_TRIDENT);
                    res.setDescription("Maxthon");
                }
                if ((ver=context.getcVersionAfterPattern("AOL ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                    res.fullVersion += " (using AOL " + ver + ")";
                    context.consume("Update a", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                } else if (context.consume("Update a", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                    res.setDescription(res.getDescription() + " (using AOL)");
                }
                if ((ver=context.getcVersionAfterPattern("R1 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                    res.fullVersion += " (using RealOne "+ver+")";
                }
            }
            return res;
        }

        if (possibleVersions.contains(",11,") &&
                (vertr=context.getcVersionAfterPattern("Trident/",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            if ((ver=context.getcVersionAfterPattern("rv:",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                if (vertr.equals("7.0") && ver.startsWith("11")) {
                    res = new Browser(Brand.MICROSOFT,BrowserFamily.IE,"IE",new RenderingEngine(Brand.MICROSOFT, RenderingEngineFamily.TRIDENT, vertr, 2), ver);

                    context.getcNextTokens(new Matcher[] {new Matcher("like", MatchingType.EQUALS),
                                               new Matcher("Gecko", MatchingType.REGEXP)
                    },
                    MatchingRegion.REGULAR);
                    setInternetExplorerWebview(context, res);
                }
            }
            if (res!=null) return res;
        }

        return null;

    }

    static Browser getBrowser(UserAgentContext context, OS os, OS[]overrideOS) {
        String userAgent = context.getUA();
        Browser res = null;
        int pos;
        String ver;
        String[]multi;

        boolean iStuff = os.getFamily() == OSFamily.IOS;

        // HTML to PDF converter of some sort
        if ((ver=context.getcVersionAfterPattern("SMIT-Browser/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
            res = new Browser(Brand.UNKNOWN,BrowserFamily.OTHER,"SMIT Browser",RenderingEngine.getUnknown(), ver);
        } else if (context.getUA().startsWith("Windows Phone Search")) {
            context.getcNextTokens(new Matcher[] {new Matcher("Windows",MatchingType.EQUALS),new Matcher("Phone",MatchingType.EQUALS),new Matcher("Search",MatchingType.EQUALS)}
            , MatchingRegion.REGULAR);
            context.consume("[0-9]\\.[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
            context.consume("[0-9]{4}", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
            res = new Browser(Brand.MICROSOFT,BrowserFamily.OTHER,"Image Search Preview",RenderingEngine.getNone());
        } else if ((ver=context.getcVersionAfterPattern("MSIEMobile ", MatchingType.BEGINS,MatchingRegion.PARENTHESIS))!=null) {
            res = new Browser(Brand.MICROSOFT,BrowserFamily.IE,"IE Mobile",getTridentVersion(context,"IE Mobile " +ver), ver);
            context.consume("MSIE ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            context.consume("IEMobile ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            UserAgentDetectionHelper.consumeMozilla(context);
        } else if ((ver=context.getcVersionAfterPattern("IEMobile ", MatchingType.BEGINS,MatchingRegion.PARENTHESIS))!=null ||
                   (ver=context.getcVersionAfterPattern("IEMobile/", MatchingType.BEGINS,MatchingRegion.PARENTHESIS))!=null) {
            res = new Browser(Brand.MICROSOFT,BrowserFamily.IE,"IE Mobile",getTridentVersion(context,"IE Mobile " +ver), ver);
            setInternetExplorerWebview(context, res);


            if (ver.equals("11.0")) {
                context.getcNextTokens(new Matcher[] {new Matcher("like", MatchingType.EQUALS),
                                           new Matcher("Gecko", MatchingType.REGEXP)
                },
                MatchingRegion.REGULAR);
                context.consume("rv:" + ver, MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            }

            context.consume("MSIE ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            UserAgentDetectionHelper.consumeMozilla(context);
        } else if ((ver=context.getcVersionAfterPattern("S40OviBrowser/", MatchingType.BEGINS,MatchingRegion.REGULAR,3))!=null) {
            res = new Browser(Brand.NOKIA,BrowserFamily.OTHER,"OviBrowser",RenderingEngine.getUnknown(), ver);
            context.consume("Gecko/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("Mozilla/", MatchingType.BEGINS, MatchingRegion.REGULAR);
        } else if ((ver=context.getcVersionAfterPattern("NintendoBrowser/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
            res = new Browser(Brand.NINTENDO,BrowserFamily.OTHER_WEBKIT,"Nintendo Browser", RenderingEngine.getUnknown(), ver);
            context.consume("NX/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("Mozilla/5.0", MatchingType.EQUALS, MatchingRegion.REGULAR);
            context.consume("KHTML, like Gecko", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);

            if ((ver=context.getcVersionAfterPattern("AppleWebKit/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                res.setRenderingEngine(new RenderingEngine(Brand.APPLE, RenderingEngineFamily.WEBKIT, ver, 2));
            }
        } else if (os.getDescription().endsWith("Nintendo 3DS") && (ver=context.getcVersionAfterPattern("Version/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
            res = new Browser(Brand.NINTENDO,BrowserFamily.OTHER_WEBKIT,"Nintendo Browser 3DS",new RenderingEngine(Brand.UNKNOWN, RenderingEngineFamily.WEBKIT), ver);
            context.consume("Mozilla/5.0", MatchingType.EQUALS, MatchingRegion.REGULAR);
        } else if (context.contains("WebKit", MatchingType.CONTAINS, MatchingRegion.BOTH) ||
                   context.contains("Webkit", MatchingType.CONTAINS, MatchingRegion.BOTH) ||
                   (context.contains("com.google.GooglePlus/", MatchingType.BEGINS,MatchingRegion.REGULAR) && iStuff)) {
            if ((ver=context.getcVersionAfterPattern("NokiaBrowser/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.NOKIA,BrowserFamily.OTHER_WEBKIT,"NokiaBrowser",getWebkitVersion(context), ver);
            } else if ((ver=context.getcVersionAfterPattern("Chromium/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.CHROMIUM,BrowserFamily.CHROME,"Chromium", getWebkitVersion(context, null, true, false), ver);
                context.consume("Chrome/", MatchingType.BEGINS,MatchingRegion.REGULAR);
            } else if ((ver=context.getcVersionAfterPattern("MxNitro/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.MAXTHON,BrowserFamily.OTHER_WEBKIT,"Nitro", getWebkitVersion(context), ver);
                context.consume("Chrome/", MatchingType.BEGINS,MatchingRegion.REGULAR);
            } else if ((ver=context.getcVersionAfterPattern("Iron/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.SRWARE,BrowserFamily.OTHER_WEBKIT,"Iron", getWebkitVersion(context), ver);
                context.consume("Chrome/", MatchingType.BEGINS,MatchingRegion.REGULAR);
            } else if ((ver = context.getcVersionAfterPattern("Lunascape/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
                context.consume("KHTML, like Gecko", MatchingType.BEGINS,MatchingRegion.PARENTHESIS);
                res = new Browser(Brand.LUNASCAPE,BrowserFamily.OTHER_WEBKIT,"Lunascape",getWebkitVersion(context), ver);
            } else if ((ver=context.getcVersionAfterPattern("Vivaldi/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.VIVALDI,BrowserFamily.OTHER_WEBKIT,"Vivaldi", getWebkitVersion(context), ver);
                context.consume("Chrome/", MatchingType.BEGINS,MatchingRegion.REGULAR);
            } else if ((ver=context.getcVersionAfterPattern("Maxthon/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.OTHER,BrowserFamily.OTHER_WEBKIT,"Maxthon", getWebkitVersion(context), ver);
                context.consume("Chrome/", MatchingType.BEGINS,MatchingRegion.REGULAR);
            } else if ((ver=context.getcVersionAfterPattern("Dragon/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.COMODO,BrowserFamily.OTHER_WEBKIT,"Dragon", getWebkitVersion(context), ver);
                context.consume("Chrome/", MatchingType.BEGINS,MatchingRegion.REGULAR);
            } else if ((ver=context.getcVersionAfterPattern("SamsungBrowser/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.SAMSUNG,BrowserFamily.OTHER_WEBKIT,"Samsung Browser", getWebkitVersion(context), ver);
                context.consume("Chrome/", MatchingType.BEGINS,MatchingRegion.REGULAR);
            } else if (os.getFamily() == OSFamily.BADA && (ver = context.getcVersionAfterPattern("Dolfin/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.SAMSUNG,BrowserFamily.OTHER,"Dolfin",getWebkitVersion(context), ver);
            } else if ((ver=context.getcVersionAfterPattern("Flock/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.NOKIA,BrowserFamily.OTHER_WEBKIT,"Flock", getWebkitVersion(context), ver);
                context.consume("Chrome/", MatchingType.BEGINS,MatchingRegion.REGULAR);
            } else if ((ver=context.getcVersionAfterPattern("YaBrowser/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.UNKNOWN,BrowserFamily.OTHER_WEBKIT,"Yandex Browser", getWebkitVersion(context), ver);
                context.consume("Chrome/", MatchingType.BEGINS,MatchingRegion.REGULAR);
            } else if ((ver=context.getcVersionAfterPattern("Edge/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.MICROSOFT,BrowserFamily.IE,"Edge", new RenderingEngine(Brand.MICROSOFT, RenderingEngineFamily.EDGE, ver, 1), ver, 1);
                context.consume("KHTML, like Gecko", MatchingType.BEGINS,MatchingRegion.PARENTHESIS);
                context.consume("Chrome/", MatchingType.BEGINS,MatchingRegion.REGULAR);
                context.consume("Mozilla/", MatchingType.BEGINS,MatchingRegion.REGULAR);
                context.consume("Safari/", MatchingType.BEGINS,MatchingRegion.REGULAR);
                context.consume("AppleWebKit/", MatchingType.BEGINS,MatchingRegion.REGULAR);
                if (os.getFamily() == OSFamily.WINDOWS_MOBILE) {
                    context.consume("Mobile", MatchingType.EQUALS,MatchingRegion.REGULAR);
                    context.consume("Android 6.0.1", MatchingType.EQUALS,MatchingRegion.PARENTHESIS);
                    context.consume("Android 4.2.1", MatchingType.EQUALS,MatchingRegion.PARENTHESIS);
                }
            } else if ((ver=context.getcVersionAfterPattern("OPR/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.OPERA,BrowserFamily.NEW_OPERA,"Opera", getWebkitVersion(context, null, false, true), ver);
                context.consume("Chrome/", MatchingType.BEGINS,MatchingRegion.REGULAR);
            } else if (context.consume("Avant TriCore", MatchingType.EQUALS,MatchingRegion.PARENTHESIS)) {
                res = new Browser(Brand.AVANT,BrowserFamily.OTHER_WEBKIT,"Avant Browser", getWebkitVersion(context));
                context.consume("Chrome/", MatchingType.BEGINS,MatchingRegion.REGULAR);
            } else if ((ver=context.getcVersionAfterPattern("Chrome/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                String cv = ver;
                String app = "";
                if ((ver=context.getcVersionAfterPattern("GSA/", MatchingType.BEGINS,MatchingRegion.REGULAR,2))!=null) {
                    app += " (with Google Search App "+ver+")";
                }
                res = new Browser(Brand.GOOGLE,BrowserFamily.CHROME,"Chrome", getWebkitVersion(context, cv, true, false), cv+app);
                if (os.getDescription().contains("Android")) {
                    if (!UserAgentDetectionHelper.greaterThan(os.getVersion(), 4) && (context.consume("Version/", MatchingType.BEGINS,MatchingRegion.REGULAR) || app.length()>0)) {
                        // https://mobiforge.com/research-analysis/webviews-and-user-agent-strings
                        res.setInWebView(true);
                    } else if (UserAgentDetectionHelper.greaterThan(os.getVersion(), 4) && context.consume("wv", MatchingType.EQUALS,MatchingRegion.PARENTHESIS)) {
                        // https://developer.chrome.com/multidevice/user-agent
                        res.setInWebView(true);
                    }
                }
            } else if ((ver=context.getcVersionAfterPattern("Arora/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.OTHER,BrowserFamily.OTHER_WEBKIT,"Arora", getWebkitVersion(context), ver);
                context.consume("KHTML, like Gecko, Safari/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            } else if ((ver=context.getcVersionAfterPattern("Scourge/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                if (context.consume("Alpha", MatchingType.EQUALS,MatchingRegion.REGULAR)) ver += " alpha";
                res = new Browser(Brand.UNKNOWN,BrowserFamily.OTHER_WEBKIT,"Scourge", getWebkitVersion(context), ver);
                context.consume("AppleWebKit", MatchingType.EQUALS,MatchingRegion.REGULAR);
            } else if ((ver=context.getcVersionAfterPattern("Surf/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                context.consume("Compatible", MatchingType.EQUALS,MatchingRegion.REGULAR);
                context.consume("Safari", MatchingType.EQUALS,MatchingRegion.PARENTHESIS);
                res = new Browser(Brand.UNKNOWN,BrowserFamily.OTHER_WEBKIT,"Surf", getWebkitVersion(context), ver);
            } else if ((ver=context.getcVersionAfterPattern("Silk/", MatchingType.BEGINS,MatchingRegion.BOTH))!=null) {
                if (os.getVendor() == Brand.SONY) {
                    res = new Browser(Brand.SONY,BrowserFamily.OTHER_WEBKIT,"NetFront fork", getWebkitVersion(context), ver); // According to http://console.maban.co.uk/device/psvita/
                } else {
                    res = new Browser(Brand.AMAZON,BrowserFamily.OTHER_WEBKIT,"Silk", getWebkitVersion(context, null, false, true), ver);
                    if (os.getVendor() == Brand.APPLE) {
                        overrideOS[0] = new OS(Brand.AMAZON, OSFamily.ANDROID, "Amazon Android", "");
                    }
                }
            } else if ((ver=context.getcVersionAfterPattern("BrowserNG/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.NOKIA,BrowserFamily.OTHER_WEBKIT,"BrowserNG", getWebkitVersion(context), ver);
            } else if ((ver=context.getcVersionAfterPattern("Epiphany/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.NOKIA,BrowserFamily.OTHER_WEBKIT,"Epiphany", getWebkitVersion(context), ver);
            } else if (context.contains("Safari/", MatchingType.BEGINS, MatchingRegion.REGULAR) && !iStuff) {
                if (os.getDescription().contains("Android")) {
                    if ((ver=context.getcVersionAfterPattern("UCBrowser/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                        res = new Browser(Brand.UCWEB,BrowserFamily.OTHER_WEBKIT,"UC Browser",getWebkitVersion(context),ver);
                        context.consume("U3/", MatchingType.BEGINS,MatchingRegion.REGULAR);
                    } else {
                        String app = "";
                        if ((ver=context.getcVersionAfterPattern("BingWeb/", MatchingType.BEGINS,MatchingRegion.REGULAR,2))!=null)
                            app = " (with Bing app "+ver+")";
                        else if ((ver=context.getcVersionAfterPattern("GoogleGoggles-Android/", MatchingType.BEGINS,MatchingRegion.REGULAR,2))!=null)  {
                            context.consume("gzip", MatchingType.EQUALS, MatchingRegion.REGULAR);
                            app = " (with Google Goggles app "+ver+")";
                        } else if ((ver=context.getcVersionAfterPattern("GSA/", MatchingType.BEGINS,MatchingRegion.REGULAR,2))!=null) {
                            app += " (with Google Search App)";
                        } else if ((ver=context.getcVersionAfterPattern("MQQBrowser/", MatchingType.BEGINS,MatchingRegion.REGULAR,2))!=null) {
                            app += " (with QQ Mobile Browser "+ver+")";
                        }
                        res = new Browser(Brand.GOOGLE,BrowserFamily.ANDROID,"Stock" + app,getWebkitVersion(context));
                        if (app.length()>0) {
                            res.setInWebView(true);
                        }
                    }
                } else if (context.contains("BlackBerry/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                    res = new Browser(Brand.RIM,BrowserFamily.OTHER_WEBKIT,"Stock",getWebkitVersion(context));
                } else if (os.getFamily() == OSFamily.WEBOS) {
                    context.consume("Version/", MatchingType.BEGINS,MatchingRegion.REGULAR);
                    if (os.getVendor() == Brand.HP)
                        context.consume("wOSBrowser/", MatchingType.BEGINS,MatchingRegion.REGULAR);
                    res = new Browser(os.getVendor(),BrowserFamily.OTHER_WEBKIT,"Stock",getWebkitVersion(context));
                } else if (context.contains("Symbian", MatchingType.BEGINS, MatchingRegion.CONSUMED)) {
                    res = new Browser(Brand.NOKIA,BrowserFamily.OTHER_WEBKIT,"Stock",getWebkitVersion(context));
                    context.consume("KHTML,like Gecko", MatchingType.EQUALS,MatchingRegion.PARENTHESIS);
                    context.consume("Mozilla/5.0", MatchingType.EQUALS,MatchingRegion.PARENTHESIS);
                } else if (context.contains("Version/", MatchingType.BEGINS, MatchingRegion.REGULAR) &&
                           (context.contains("Mac OS", MatchingType.CONTAINS, MatchingRegion.CONSUMED) ||
                            context.contains("Windows NT", MatchingType.BEGINS, MatchingRegion.CONSUMED))) {
                    context.getcNextTokens(new Matcher[] {new Matcher("Public", MatchingType.EQUALS),
                                               new Matcher("Beta", MatchingType.EQUALS)
                    },
                    MatchingRegion.REGULAR);

                    res = new Browser(Brand.APPLE,BrowserFamily.SAFARI,"Safari",getWebkitVersion(context), getVersionVersion(context));
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
                    } else if ((ver=context.getcVersionAfterPattern("MQQBrowser/", MatchingType.BEGINS,MatchingRegion.REGULAR,2))!=null) {
                        app = " (with QQ Mobile Browser "+ver+")";
                    } else if (context.consume("DiigoBrowser", MatchingType.BEGINS,MatchingRegion.REGULAR)) {
                        app = " (with Diigo browser)";
                    }

                    res = new Browser(Brand.APPLE,BrowserFamily.IOS,"Stock",getWebkitVersion(context), app);

                    context.consume("Mobile/", MatchingType.BEGINS,MatchingRegion.REGULAR);

                    if (!context.consume("Version/", MatchingType.BEGINS,MatchingRegion.REGULAR) || app.length()>0) {
                        // https://mobiforge.com/research-analysis/webviews-and-user-agent-strings
                        res.setInWebView(true);
                    }
                } else {
                    res = new Browser(Brand.UNKNOWN,BrowserFamily.OTHER_WEBKIT,"WebKit-based",getWebkitVersion(context));
                }
            }
            context.consume("Version/", MatchingType.BEGINS,MatchingRegion.REGULAR);
        } else if ((ver=context.getcVersionAfterPattern("Konqueror/", MatchingType.BEGINS,MatchingRegion.PARENTHESIS))!=null) {
            UserAgentDetectionHelper.consumeMozilla(context);
            context.consume("(KHTML, )?like Gecko", MatchingType.REGEXP,MatchingRegion.PARENTHESIS);
            context.consume("20[01][0-9][01][0-9][0-3][0-9]", MatchingType.REGEXP,MatchingRegion.PARENTHESIS);
            res = new Browser(Brand.KDE,BrowserFamily.KHTML,"Konqueror",getKHTMLVersion(context), ver);
        } else if ((ver=context.getcVersionAfterPattern("Polaris/", MatchingType.BEGINS,MatchingRegion.PARENTHESIS))!=null) {
            res = new Browser(Brand.INFRAWARE, BrowserFamily.OTHER, "Polaris", RenderingEngine.getOther(Brand.INFRAWARE), ver);
        } else if (context.contains("KHTML, like Gecko", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) ||
                   context.contains("KHTML/", MatchingType.BEGINS, MatchingRegion.REGULAR)) {
            UserAgentDetectionHelper.consumeMozilla(context);
            context.consume("like Gecko", MatchingType.EQUALS,MatchingRegion.PARENTHESIS);
            res = new Browser(Brand.KDE,BrowserFamily.KHTML,"KHTML-based",getKHTMLVersion(context));
        } else if ((ver=context.getcVersionAfterPattern("NetFront/", MatchingType.BEGINS,MatchingRegion.BOTH))!=null ||
                   (ver=context.getcVersionAfterPattern("Browser/NetFront/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {

            String ver2;
            if ((ver2=context.getcVersionAfterPattern("Novarra-Vision/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.NOVARRA,BrowserFamily.OTHER,"Vision",RenderingEngine.getUnknown(), ver2);
            } else {
                res = new Browser(Brand.ACCESSCO,BrowserFamily.NETFRONT,"NetFront",RenderingEngine.getUnknown(), ver);
            }

            context.consume("NetFront/", MatchingType.BEGINS, MatchingRegion.BOTH);
        } else if (context.contains("Mozilla/3.0", MatchingType.EQUALS, MatchingRegion.REGULAR) &&
                   context.consume("Sun", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            res = new Browser(Brand.SUN, BrowserFamily.OTHER, "HotJava", RenderingEngine.getOther(Brand.SUN));
            context.consume("Mozilla/3.0", MatchingType.EQUALS, MatchingRegion.REGULAR);
        } else if ((ver=context.getcVersionAfterPattern("Lynx/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
            res = new Browser(Brand.UNKNOWN,BrowserFamily.TEXTBASED,"Lynx",RenderingEngine.getText(), ver);

            context.consume("libwww-FM/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("SSL-MM/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("OpenSSL/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("libwen-US/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("Sen-US/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("GNUTLS/", MatchingType.BEGINS, MatchingRegion.REGULAR);

        } else if (context.consume("ELinks", MatchingType.EQUALS,MatchingRegion.REGULAR)) {
            ver = context.getcToken("[0-9]+\\.[0-9\\.a-zA-Z-]+", MatchingType.REGEXP,MatchingRegion.PARENTHESIS);
            if (ver == null) ver = "";
            res = new Browser(Brand.UNKNOWN,BrowserFamily.TEXTBASED,"ELinks",RenderingEngine.getText(), ver);
        } else if ((ver = context.getcVersionAfterPattern("ELinks/", MatchingType.BEGINS,MatchingRegion.REGULAR)) != null ||
                   ((ver = context.getcVersionAfterPattern("ELinks/", MatchingType.BEGINS,MatchingRegion.PARENTHESIS)) != null && context.consume("Mozilla/5.0", MatchingType.EQUALS,MatchingRegion.REGULAR))) {
            res = new Browser(Brand.UNKNOWN,BrowserFamily.TEXTBASED,"ELinks",RenderingEngine.getText(), ver);
            context.consume("textmode", MatchingType.EQUALS,MatchingRegion.PARENTHESIS);
            context.consume("[0-9]+x[0-9]+(-[0-9])?", MatchingType.REGEXP,MatchingRegion.PARENTHESIS);
        } else if (context.consume("Links", MatchingType.EQUALS,MatchingRegion.REGULAR)) {
            ver = context.getcToken("[0-9]+\\.[0-9\\.a-zA-Z-]+", MatchingType.REGEXP,MatchingRegion.PARENTHESIS);
            if (ver == null) ver = "";
            res = new Browser(Brand.UNKNOWN,BrowserFamily.TEXTBASED,"Links",RenderingEngine.getText(), ver);
        } else if ((ver=context.getcVersionAfterPattern("w3m/", MatchingType.BEGINS,MatchingRegion.REGULAR))!=null) {
            res = new Browser(Brand.UNKNOWN,BrowserFamily.TEXTBASED,"w3m",RenderingEngine.getText(), ver);
            context.consume("Lynx compatible", MatchingType.EQUALS,MatchingRegion.PARENTHESIS);
        } else if (context.contains("Mozilla/4.61", MatchingType.EQUALS, MatchingRegion.REGULAR) &&
                   context.consume("BrowseX", MatchingType.EQUALS, MatchingRegion.REGULAR)) {
            context.consume("Mozilla/4.61", MatchingType.EQUALS, MatchingRegion.REGULAR);
            context.consume("-", MatchingType.EQUALS, MatchingRegion.REGULAR);
            pos = context.getUA().indexOf("BrowseX (");
            ver = UserAgentDetectionHelper.getVersionNumber(context.getUA(), pos+9);
            res = new Browser(Brand.UNKNOWN,BrowserFamily.OTHER,"BrowseX",RenderingEngine.getUnknown(), ver);
            context.consume(ver, MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
        } else if ((ver = context.getcVersionAfterPattern("Gecko/", MatchingType.BEGINS, MatchingRegion.REGULAR))!=null ||
                   context.contains("Galeon/",  MatchingType.BEGINS, MatchingRegion.REGULAR) ||
                   context.contains("GranParadiso/",  MatchingType.BEGINS, MatchingRegion.REGULAR) ||
                   (ver = context.getcVersionAfterPattern("Mozilla/5.0/Gecko/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res = tryOpera(context);
            if (res == null) {
                res = getGecko(context, ver, os);
            } else {
                context.consume("Firefox/", MatchingType.BEGINS, MatchingRegion.REGULAR);
                context.consume("rv:", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
            }
            context.consume("Mozilla/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("Mozilla", MatchingType.EQUALS, MatchingRegion.REGULAR);
        } else if (context.contains("Gecko", MatchingType.BEGINS, MatchingRegion.BOTH) && !context.contains("Trident/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
            res = getGecko(context,"", os);
            context.consume("Mozilla/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("Gecko", MatchingType.BEGINS, MatchingRegion.REGULAR);
        } else if ((ver = context.getcVersionAfterPattern("UP.Browser/", MatchingType.BEGINS, MatchingRegion.REGULAR, 3)) != null ||
                   (ver = context.getcVersionAfterPattern("Browser/UP.Browser/", MatchingType.BEGINS, MatchingRegion.REGULAR, 3)) != null) {
            res = new Browser(Brand.OPENWAVE,BrowserFamily.OTHER,"Mobile Browser", RenderingEngine.getOther(Brand.OPENWAVE), ver);
            context.consume("MMP/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            while (context.consume("GUI", MatchingType.EQUALS, MatchingRegion.PARENTHESIS));
            context.consume("Browser/UP.Browser/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("UP/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.consume("OPWV-GEN-", MatchingType.BEGINS, MatchingRegion.REGULAR);
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
            res = new Browser(Brand.OPERA,BrowserFamily.OPERA,"Opera Mobi", getPrestoVersion(context, version), version.trim());
            context.consume("Opera/9.(80|7)",  MatchingType.REGEXP, MatchingRegion.REGULAR);
        } else if ((ver = context.getcVersionAfterPattern("NetPositive/",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            UserAgentDetectionHelper.consumeMozilla(context);
            res = new Browser(Brand.BE,BrowserFamily.OTHER,"NetPositive",RenderingEngine.getUnknown(), ver);
        } else if ((ver = context.getcVersionAfterPattern("Acorn-HTTP/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
            res = new Browser(Brand.ACORN,BrowserFamily.OTHER,"Acorn HTTP",RenderingEngine.getUnknown(), ver);
            UserAgentDetectionHelper.consumeMozilla(context);
            context.consume("Compatible", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        } else if ((ver = context.getcVersionAfterPattern("Oregano ",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            res = new Browser(Brand.OREGAN,BrowserFamily.OTHER,"Oregano",RenderingEngine.getUnknown(), ver);
            UserAgentDetectionHelper.consumeMozilla(context);
            context.consume("Compatible", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        } else if (os.getVendor() == Brand.NINTENDO && context.getUA().startsWith("Opera/9.50") && context.getUA().contains("DSi") &&
                   (ver = context.getcVersionAfterPattern("Opera/",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
            res = new Browser(Brand.OPERA,BrowserFamily.OPERA,"Opera For DSi",new RenderingEngine(Brand.OPERA, RenderingEngineFamily.PRESTO, "2.1", 2), ver); // See http://en.wikipedia.org/wiki/Nintendo_DS_%26_DSi_Browser
            context.consume("Opera/9.50", MatchingType.EQUALS, MatchingRegion.REGULAR);
        } else




            // -----------------------------
            if (context.contains("Mozilla/4\\.[01]", MatchingType.REGEXP, MatchingRegion.REGULAR) &&
                    context.contains("compatible",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {

                res = tryOpera(context);
                if (res == null) {
                    if ((ver = context.getcVersionAfterPattern("Lotus-Notes/",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                        res = new Browser(Brand.IBM,BrowserFamily.OTHER,"Lotus Notes",RenderingEngine.getOther(Brand.IBM), ver);
                    } else if (os.getVendor() == Brand.PALM && (ver = context.getcVersionAfterPattern("Blazer/",  MatchingType.BEGINS, MatchingRegion.PARENTHESIS))!=null) {
                        res = new Browser(Brand.HANDSPRING,BrowserFamily.OTHER,"Blazer",RenderingEngine.getUnknown(), ver);
                        context.consume("MSIE 6.0",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                    }
                }
                if (res == null) res = tryGetIE(context,"4,5,6,7,8,", os);
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
                    res = tryGetIE(context,"8,9,10,", os);
                    if (res != null) {
                        context.consume("compatible",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                    }
                }
                if (res == null) {
                    res = tryGetIE(context,",11,", os);
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
                    res = new Browser(Brand.OPERA,BrowserFamily.OPERA,"Opera",getPrestoVersion(context, ver), ver);
                }
            } else if ((ver = context.getcVersionAfterPattern("amaya/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.OTHER,BrowserFamily.OTHER,"Amaya",RenderingEngine.getUnknown(), ver);
                context.consume("libwww/",  MatchingType.BEGINS, MatchingRegion.REGULAR);
            } else if ((ver = context.getcVersionAfterPattern("Dillo/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.OTHER,BrowserFamily.OTHER,"Dillo",RenderingEngine.getOther(Brand.OTHER), ver);
            } else if ((ver = context.getcVersionAfterPattern("WAP/OBIGO/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
                res = new Browser(Brand.OBIGO,BrowserFamily.OTHER,"Obigo",RenderingEngine.getUnknown(), ver);
            }



        if (res == null) {

            // We will interpret Mozilla/4.x as Netscape Communicator is and only if x is not 0 or 5
            // Don't ask why.
            if (userAgent.startsWith("Mozilla/4.") &&
                    !userAgent.startsWith("Mozilla/4.0 ") &&
                    !userAgent.startsWith("Mozilla/4.5 ")) {
                if (context.consume("OffByOne",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                    res = new Browser(Brand.OTHER,BrowserFamily.OTHER,"Off By One",RenderingEngine.getUnknown());
                    context.consume("Mozilla/4.",  MatchingType.BEGINS, MatchingRegion.REGULAR);
                    // That's a browser by Home Page Software Inc.
                } else {
                    ver = context.getcVersionAfterPattern("Mozilla/", MatchingType.BEGINS, MatchingRegion.REGULAR);
                    if (ver == null) ver = "";
                    res = new Browser(Brand.NETSCAPE,BrowserFamily.OTHER,"Communicator",RenderingEngine.getOther(Brand.NETSCAPE), ver);
                    context.consume("I",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                    context.consume("Nav",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                }
                context.consume("compatible",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            } else
                return new Browser(Brand.UNKNOWN,BrowserFamily.UNKNOWN,"",RenderingEngine.getUnknown());
        }
        return res;
    }

    static Device getDevice(UserAgentContext context, Browser b, OS o) {
        String ua = context.getUA();
        String arm = "ARM";
        String atom = "Intel Atom";

        String ver;
        String[]vers;
        // Bots & SDKs
        if (o.getFamily() == OSFamily.ANDROID &&
                (context.consume("sdk ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) ||
                 context.consume("Android SDK ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) ||
                 context.consume("google_sdk ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)))
            return new Device("",DeviceType.SDK,Brand.GOOGLE,"Android sdk");
        if (context.consume("iPhone Simulator", MatchingType.EQUALS, MatchingRegion.PARENTHESIS))
            return new Device("",DeviceType.SDK,Brand.APPLE,"iPhone Simulator");

        // Nokia stuff
        //if (context.getcToken("Nokia7650/", MatchingType.BEGINS, MatchingRegion.BOTH) != null) return new Device("",DeviceType.BOT,Brand.UNKNOWN,"COUCOUCOUCOU");
        if (o.getVendor() == Brand.NOKIA) {
            Device res = new Device(arm,DeviceType.PHONE,Brand.NOKIA,"");
            if (context.getcToken("NokiaN95", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.setDevice("N95");
            if (context.getcToken("NokiaN9", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.setDevice("N9");
            if (o.getDescription().equals("Series40") || o.getDescription().equals("Symbian OS")) {
                if (context.getcToken("Nokia311", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.setDevice("Asha 311");
                if (context.getcToken("NokiaX3-02", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.setDevice("X3 Touch and Type");
                if (context.getcToken("Nokia305", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.setDevice("Asha 305");
                if (context.getcToken("NokiaC3-00", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.setDevice("C3-00");
                if (context.getcToken("NokiaC7-00", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.setDevice("C7-00");
                if (context.getcToken("Nokia202", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.setDevice("Asha 202");
                if (context.getcToken("Nokia 3650", MatchingType.EQUALS, MatchingRegion.PARENTHESIS) != null) res.setDevice("3650");
                if (context.getcToken("Nokia6300", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.setDevice("6300");
                if (context.getcToken("Nokia7650/", MatchingType.BEGINS, MatchingRegion.REGULAR) != null) res.setDevice("7650");
                if (context.getcToken("NokiaX2-02", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.setDevice("X2-02");
                if (context.getcToken("NokiaX6-00", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.setDevice("X6-00");
                if (context.getcToken("NokiaN73", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.setDevice("N73");
                if (context.getcToken("NokiaN8-", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.setDevice("N8");
                if (context.getcToken("NokiaN81-", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.setDevice("N81");
                if (context.getcToken("NokiaE5-", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.setDevice("E5");
                if (context.getcToken("NokiaE51-", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.setDevice("E51");
                if (context.getcToken("NokiaE63-", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.setDevice("E63");
                if (context.getcToken("NokiaE71-", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.setDevice("E71");
                if (context.getcToken("NokiaE60", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.setDevice("E60");
                if (context.getcToken("NokiaE90", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.setDevice("E90");
                if (context.getcToken("NokiaN85-", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.setDevice("N85");
                if (context.getcToken("NokiaN86-", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.setDevice("N86");
                if (context.getcToken("NokiaN72/", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.setDevice("N72");
                if (context.getcToken("NokiaN93-", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.setDevice("N93");

                if (context.getcToken("Nokia808PureView/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.setDevice("808 PureView");
                if (context.getcToken("Nokia5233/", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.setDevice("5233");
                if (context.getcToken("Nokia5230/", MatchingType.BEGINS, MatchingRegion.BOTH) != null) res.setDevice("5230");
                if (context.getcToken("Nokia500/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.setDevice("500");
                if (context.getcToken("Nokia701", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.setDevice("701");
                if (context.getcToken("Nokia3230", MatchingType.BEGINS, MatchingRegion.REGULAR) != null) res.setDevice("3230");
                if (context.getcToken("es50", MatchingType.EQUALS, MatchingRegion.REGULAR) != null) res.setDevice("ES50");
                if (context.getcToken("es61", MatchingType.EQUALS, MatchingRegion.REGULAR) != null) res.setDevice("ES61");
                if (context.getcToken("es61i", MatchingType.EQUALS, MatchingRegion.REGULAR) != null) res.setDevice("ES61");
                if (context.getcToken("Nokia[ ]?6630/.*", MatchingType.REGEXP, MatchingRegion.BOTH) != null) res.setDevice("6630");
                if (context.getcToken("Nokia5530c-2/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.setDevice("5530 XpressMusic");
                if (context.getcToken("Nokia5800d", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) != null) res.setDevice("5800 XpressMusic");
            }
            if (context.consume("NokiaN-GageQD", MatchingType.BEGINS, MatchingRegion.REGULAR)) {
                context.consume("SymbianOS/", MatchingType.BEGINS, MatchingRegion.REGULAR);
                context.consume("[0-9]\\.[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
                res.setDevice("N-Gage");
                res.setDeviceType(DeviceType.CONSOLE);
            }
            if (res.getDevice().length()>0) return res;

            if (context.getUA().startsWith("SonyEricsson")) {
                res = new Device(arm,DeviceType.PHONE,Brand.SONY,"");
                if (context.consume("SonyEricssonU5", MatchingType.BEGINS, MatchingRegion.REGULAR)) res.setDevice("Vivaz");
                if (context.consume("SonyEricssonU1[ai]/.*", MatchingType.REGEXP, MatchingRegion.REGULAR)) res.setDevice("Satio");
                if (res.getDevice().length()==0) {
                    ver = context.getcVersionAfterPattern("SonyEricsson", MatchingType.BEGINS, MatchingRegion.REGULAR);
                    res = new Device(arm,DeviceType.PHONE,Brand.SONY,ver);
                }
                return res;
            }
        }

        if (o.getFamily() == OSFamily.WEBOS) {
            if (o.getVendor() == Brand.PALM) {
                if ((ver = context.getcVersionAfterPattern("Pixi/", MatchingType.BEGINS, MatchingRegion.REGULAR)) != null)
                    return new Device(arm,DeviceType.PHONE,Brand.PALM,"Pixi " + ver, true);
                if ((ver = context.getcVersionAfterPattern("Pre/", MatchingType.BEGINS, MatchingRegion.REGULAR)) != null)
                    return new Device(arm,DeviceType.PHONE,Brand.PALM,"Pre " + ver, true);
                if ((ver = context.getcVersionAfterPattern("P160UNA/", MatchingType.BEGINS, MatchingRegion.REGULAR)) != null)
                    return new Device(arm,DeviceType.PHONE,Brand.HP,"Veer 4G " + ver, true);
            }
            if (o.getVendor() == Brand.HP) {
                if ((ver = context.getcVersionAfterPattern("TouchPad/", MatchingType.BEGINS, MatchingRegion.REGULAR)) != null)  {
                    context.consume("hp-tablet", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                    return new Device(arm,DeviceType.TABLET,Brand.HP,"TouchPad " + ver, true);
                }
            }
        } else if (o.getVendor() == Brand.PALM) {
            context.consume("16;[0-9]+x[0-9]+", MatchingType.REGEXP, MatchingRegion.REGULAR);
            if (context.consume("PalmSource/Palm-D053", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                context.consume("Palm680", MatchingType.BEGINS, MatchingRegion.REGULAR);
                return new Device(arm,DeviceType.PHONE,Brand.PALM,"Treo 680");
            }
            if (context.consume("/Palm 500v/" , MatchingType.BEGINS, MatchingRegion.REGULAR)) return new Device(arm,DeviceType.PHONE,Brand.PALM,"Treo 500v", true);
            if (context.consume("PalmSource/Palm-D052" , MatchingType.BEGINS, MatchingRegion.PARENTHESIS )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"Treo 700p", true);
            if (context.consume("Palm750/v0100" , MatchingType.BEGINS, MatchingRegion.REGULAR )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"750", true);
            if (context.consume("Palm750/v0000" , MatchingType.BEGINS, MatchingRegion.REGULAR )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"Treo 750w", true);
            if (context.consume("PalmSource/Palm-D060" , MatchingType.BEGINS, MatchingRegion.PARENTHESIS )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"Treo 755p", true);
            if (context.consume("Treo800w/v0100" , MatchingType.BEGINS, MatchingRegion.REGULAR )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"Treo 800w", true);
            if (context.consume("Treo850/v0100" , MatchingType.BEGINS, MatchingRegion.REGULAR )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"Treo850", true);
            if (context.consume("Alltel_Treo850e" , MatchingType.BEGINS, MatchingRegion.REGULAR )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"Treo850e", true);
            if (context.consume("PalmSource/Palm-TnT5" , MatchingType.BEGINS, MatchingRegion.PARENTHESIS  )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"Treo 600", true);
            if (context.consume("PalmSource/Palm-TunX" , MatchingType.BEGINS, MatchingRegion.PARENTHESIS  )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"Tunx", true);
            if (context.consume("PalmSource/hspr-H102" , MatchingType.BEGINS, MatchingRegion.PARENTHESIS  )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"Treo 650", true);
            if (context.consume("PalmSource/Palm-D050" , MatchingType.BEGINS, MatchingRegion.PARENTHESIS  )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"TX", true);
            if (context.consume("PalmSource/Palm-D062" , MatchingType.BEGINS, MatchingRegion.PARENTHESIS  )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"Centro", true);
            if (context.consume("PalmSource/" , MatchingType.BEGINS, MatchingRegion.PARENTHESIS  )) return new Device(arm,DeviceType.PHONE,Brand.PALM,"", true);
        }
        // Android devices
        if (o.getFamily() == OSFamily.ANDROID) {
            context.consume("Dalvik/", MatchingType.BEGINS, MatchingRegion.REGULAR);

            // Samsung
            if (context.contains("SAMSUNG[- ]SGH-.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS) ||
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
                else if (context.consume("(SAMSUNG-)?SGH-I337.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S4");
                else if (context.consume("(SAMSUNG )?SGH-M919.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S4");
                else if (context.consume("(SAMSUNG-)?SGH-I407.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Amp");
                else if (context.consume("(SAMSUNG-)?SGH-I897.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Captivate");
                else if (context.consume("(SAMSUNG-)?SGH-I7[27]7.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S2");
                else if (context.consume("(SAMSUNG-)?SGH-I717.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note");
                else if (context.consume("(SAMSUNG-)?SGH-I317.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note 2");
                else if (context.consume("(SAMSUNG-)?SGH-T679.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Exhibit II 4G");
                else if (context.consume("(SAMSUNG-)?SGH-I997.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Infuse 4G");
                else if (context.consume("(SAMSUNG )?SGH-T849.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 7.0");
                else if (context.consume("(SAMSUNG )?SGH-T859.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 10.1");
                else if (context.consume("(SAMSUNG )?SGH-T499.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Dart");
                else if (context.consume("(SAMSUNG )?SGH-T589.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Gravity Smart");
                else if (context.consume("(SAMSUNG )?SGH-T839.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Sidekick 4G");
                else if (context.consume("(SAMSUNG )?SGH-T399.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) device = new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Light");

                if (device != null) {
                    if (context.contains("(SAMSUNG[- ])SGH-..../.*", MatchingType.REGEXP, MatchingRegion.CONSUMED)) {
                        context.consume("Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
                    }
                    device.setTouch(true);
                    return device;
                }

                return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Unknown");
            }

            if (context.contains("SAMSUNG GT-", MatchingType.BEGINS, MatchingRegion.PARENTHESIS) ||
                    context.contains("GT-", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                context.consume("Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
                if (context.consume("(SAMSUNG )?GT-I9100.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S2", true);
                if (context.consume("(SAMSUNG )?GT-S6102.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Y Duos", true);
                if (context.consume("(SAMSUNG )?GT-S5839i.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Ace", true);
                if (context.consume("(SAMSUNG )?GT-S5830.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Ace", true);
                if (context.consume("(SAMSUNG )?GT-S5690.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Xcover", true);
                if (context.consume("(SAMSUNG )?GT-S5670.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Fit", true);
                if (context.consume("(SAMSUNG )?GT-S5660.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Gio", true);
                if (context.consume("(SAMSUNG )?GT-S536[0-3].*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Y", true);
                if (context.consume("(SAMSUNG )?GT-S5570.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Mini", true);
                if (context.consume("(SAMSUNG )?GT-S7275R.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Ace 3", true);
                if (context.consume("(SAMSUNG )?GT-S7562.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S Duos", true);

                if (context.consume("(SAMSUNG )?GT-P75[01]0.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 10.1", true);
                if (context.consume("(SAMSUNG )?GT-P68[01]0.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 7.7", true);
                if (context.consume("(SAMSUNG )?GT-P73[01]0.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 8.9", true);
                if (context.consume("(SAMSUNG )?GT-P6200.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 7 Plus", true);
                if (context.consume("(SAMSUNG )?GT-P51[01]0.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 2 10.1", true);
                if (context.consume("(SAMSUNG )?GT-P5113.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 2 10.1", true);
                if (context.consume("(SAMSUNG )?GT-P5210.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 3 10.1", true);
                if (context.consume("(SAMSUNG )?GT-P3113.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 2 7", true);
                if (context.consume("(SAMSUNG )?GT-P31[01]0.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 2 7", true);
                if (context.consume("(SAMSUNG )?GT-P10[01]0.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab", true);
                if (context.consume("(SAMSUNG )?GT-P6210.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab", true);

                if (context.consume("(SAMSUNG )?GT-N80[01]0.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Note 10.1", true);
                if (context.consume("(SAMSUNG )?GT-N8005.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Note 10.1", true);
                if (context.consume("(SAMSUNG )?GT-N8013.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note", true);
                if (context.consume("(SAMSUNG )?GT-N5110.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Note 8.0", true);
                if (context.consume("(SAMSUNG )?GT-N7105.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note 2", true);
                if (context.consume("(SAMSUNG )?GT-N7100.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note 2", true);
                if (context.consume("(SAMSUNG )?GT-N7100.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note 2", true);
                if (context.consume("(SAMSUNG )?GT-N7000.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note", true);
                //TODO: UNTESTED
                if (context.consume("(SAMSUNG )?GT-5100.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Note 8.0");

                if (context.consume("(SAMSUNG )?GT-I5510.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy 551", true);
                if (context.consume("(SAMSUNG )?GT-I8190.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3 Mini", true);
                if (context.consume("(SAMSUNG )?GT-I5500.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy 5", true);
                if (context.consume("(SAMSUNG )?GT-I9001.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S Plus", true);
                if (context.consume("(SAMSUNG )?GT-I5700.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Spica", true);
                if (context.consume("(SAMSUNG )?GT-I9305T.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3", true);
                if (context.consume("(SAMSUNG )?GT-I930[05].*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3", true);
                if (context.consume("(SAMSUNG )?GT-I950[056].*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S4", true);
                if (context.consume("(SAMSUNG )?GT-I9515.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S4 Value Edition", true);
                if (context.consume("(SAMSUNG )?GT-I9220.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note", true);
                if (context.consume("(SAMSUNG )?GT-I9295.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S4 Active", true);
                if (context.consume("(SAMSUNG )?GT-I919[05].*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S4 Mini", true);
                if (context.consume("(SAMSUNG )?GT-I9000.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S", true);
                if (context.consume("(SAMSUNG )?GT-I9003.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy SL", true);
                if (context.consume("(SAMSUNG )?GT-I8160.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Ace 2", true);
                if (context.consume("(SAMSUNG )?GT-I5800.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy 3", true);
                if (context.consume("(SAMSUNG )?GT-I5801.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Apollo", true);
                if (context.consume("(SAMSUNG )?GT-I8150.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy W", true);


                if (context.consume("(SAMSUNG )?GT-B5510.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Y Pro", true);
                if (context.consume("(SAMSUNG )?GT-B7510.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Pro", true);

                if (context.consume("(SAMSUNG )?GT-S7262.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Star Pro/Plus", true);

                return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Unknown", true);
            }


            if (context.consume("Galaxy S II", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S2", true);
            if (context.consume("SHV-E120K ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S2", true);
            if (context.consume("Galaxy Build", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy", true);
            if (context.consume("SCH-R950", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                context.consume("USCC-R950", MatchingType.EQUALS, MatchingRegion.REGULAR);
                return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note 2", true);
            }
            if (context.consume("SCH-R530U", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3", true);
            if (context.consume("SCH-I939", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3", true);
            if (context.consume("SCH-I605", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note 2", true);
            if (context.consume("SCH-I535", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3", true);
            if (context.consume("SCH-I545", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S4", true);
            if (context.consume("SCH-I500", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S", true);
            if (context.consume("SC-06D", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3", true);
            if (context.consume("SPH-M820", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Prevail", true);
            if (context.consume("SPH-L900", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note 2", true);
            if (context.consume("SPH-L710", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3", true);
            if (context.consume("(SAMSUNG )?SPH-L720T .*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S4", true);
            if (context.consume("SPH-D710", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S2", true);
            if (context.consume("SPH-M920", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Transform", true);
            if (context.consume("SPH-M900", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Moment", true);
            if (context.consume("SPH-D700", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Epic 4G", true);
            if (context.consume("SPH-M910", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Intercept", true);
            if (context.consume("SPH-M930", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Transform Ultra", true);
            if (context.consume("SPH-P100", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 7", true);
            if (context.consume("SPH-D600", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Conquer 4G", true);

            if (context.consume("SHW-M380[KW] .*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 10.1", true);
            if (context.consume("SHW-M250K ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S2", true);
            if (context.consume("SHW-M110S ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S", true);
            if (context.consume("SHW-M440S ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3", true);
            if (context.consume("SHV-E210S ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3", true);
            if (context.consume("SHV-E210L ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3", true);
            if (context.consume("SHV-E210K ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S3", true);
            if (context.consume("SHV-E160[SK] .*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note", true);
            if (context.consume("SM-N7505 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note 3 Neo", true);
            if (context.consume("(SAMSUNG[ -])?SM-N900[AVSPT56]?(-ORANGE)?[ /].*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note 3", true);
            if (context.consume("(SAMSUNG[ -])?SM-N900(W8|0Q)(-ORANGE)?[ /].*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note 3", true);
            if (context.consume("(SAMSUNG[ -])?SM-G870A[ /].*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S5 Active", true);
            if (context.consume("(SAMSUNG[ -])?SM-G90[01][VATF][ -].*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S5", true);
            if (context.consume("(SAMSUNG[ -])?SM-G350(2T)? .*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Core Plus", true);
            if (context.consume("(SAMSUNG[ -])?SM-T21(1|7S|7A|0R|0|05) .*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 3 7.0", true);
            if (context.consume("SM-T230 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 4 7.0", true);
            if (context.consume("SM-T310 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 3 8.0", true);
            if (context.consume("SM-T805 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab S 10.5", true);
            if (context.consume("(SAMSUNG[ -])?SM-T320 .*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab Pro 8.4", true);
            if (context.consume("(SAMSUNG[ -])?SM-T550 .*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab A 9.7", true);
            if (context.consume("(SAMSUNG[ -])?SM-T900 .*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab Pro 12.2", true);
            if (context.consume("SM-T520 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab Pro 10.1", true);
            if (context.consume("SM-T530 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab 4 10.1", true);
            if (context.consume("(SAMSUNG[ -])?SM-T800 .*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Tab S 10.5", true);
            if (context.consume("SM-G800F ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S5 Mini", true);
            if (context.consume("SM-P600 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Note 10.1", true);
            if (context.consume("(SAMSUNG[ -])?SM-P900 .*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SAMSUNG,"Galaxy Note Pro 12.2", true);
            if (context.consume("(SAMSUNG[ -])?SM-N910([TGSAUHVFCP]|W8)(-ORANGE| |/[A-Z0-9]+).*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note 4", true);
            if (context.consume("(SAMSUNG[ -])?(SM-)?N9100 .*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Note 4 Dual Sim", true);
            if (context.consume("SM-G386F ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Core", true);
            if (context.consume("SM-G850M ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Alpha", true);
            if (context.consume("SM-A300FU ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy A3", true);
            if (context.consume("(SAMSUNG )?SM-G850F.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Alpha", true);
            if (context.consume("(SAMSUNG[ -])?SM-G920([TAF]|W8)(-ORANGE| |/[A-Z0-9]+).*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S6", true);
            if (context.consume("(SAMSUNG[ -])?SM-G357FZ.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy Ace 4", true);
            if (context.consume("(SAMSUNG[ -])?SM-G950[UF].*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Galaxy S8", true);

            // KTTECH
            if (context.consume("KM-E100", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.KTTECH,"KM-E100", true);

            // ZTE
            if (context.consume("ZTE-N880E", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.ZTE,"N880E", true);
            if (context.consume("ZTE U970_TD/1.0", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.ZTE,"Grand X", true);
            if (context.consume("ZTE N880E", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.ZTE,"N880E", true);
            if (context.consume("ZTE Z992", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.ZTE,"Z992", true);
            if (context.consume("Z995", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.ZTE,"Z995", true);
            if (context.consume("Z730", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.ZTE,"Concord II", true);
            if (context.consume("Orange Tactile internet 2", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.ZTE,"Blade", true);
            if (context.consume("ZTE V768", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.ZTE,"Concord (V768)", true);
            if (context.consume("ZTE-RACER", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.ZTE,"Racer", true);
            if (context.consume("ZTE-BLADE", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.ZTE,"Blade", true);
            if (context.consume("ZTE-U V880", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.ZTE,"Blade V880", true);
            if (context.consume("ZTE-Z667G", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.ZTE,"Whirl 2", true);

            // Huawei
            if (context.consume("U8220", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Pulse U8220", true);
            if (context.consume("U8350", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Boulder U8350", true);
            if (context.consume("Huawei U8800", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Ideos X5", true);
            if (context.consume("U8180", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Boulder Ideos X1", true);
            if (context.consume("HUAWEI-M835", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Ideos", true);
            if (context.consume("HUAWEI-M860", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Ascend", true);
            if (context.consume("H866C", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Ascend Y", true);
            if (context.consume("HUAWEI_T8620_", MatchingType.BEGINS, MatchingRegion.REGULAR)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Ascend Y200T (T8620)", true);
            if (context.consume("T-Mobile myTouch Build/HuaweiU8680", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"myTouch (8680)", true);
            if (context.consume("Prism Build/HuaweiU8651", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Prism (8651)", true);
            if (context.consume("U8815", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Ascend G300 (U8815)", true);
            if (context.consume("HUAWEI U8950", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Ascend G600 (U8950)", true);
            if (context.consume("Huawei-U8665", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Fusion 2", true);
            if (context.consume("Huawei-U8652", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Fusion U8652", true);
            if (context.consume("TURKCELL MaxiPRO5", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Honor U8860", true);
            if (context.consume("HUAWEI MT7-L09 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Ascend Mate 7", true);
            if (context.consume("H60-L04 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Honor 6", true);
            if (context.consume("U8650 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HUAWEI,"Sonic", true);

            // SONY
            if (context.consume("SonyST23i ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Miro", true);
            if (context.consume("SonyST21i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia", true);
            if (context.consume("(SonyEricsson)?U20i.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia X10 mini pro", true);
            if (context.consume("SonyLT30p", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia T", true);
            if (context.consume("Sony Tablet S", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SONY,"Tablet S", true);
            if (context.consume("SonyEricssonLT22i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia P", true);
            if (context.consume("SonyEricssonLT15a", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Arc", true);
            if (context.consume("SonyEricssonE10i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia X10 Mini", true);
            if (context.consume("SonyEricssonU20a", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia X10 Mini Pro", true);
            if (context.consume("SonyEricssonMT15i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Neo", true);
            if (context.consume("SonyEricssonMT11i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Neo V", true);
            if (context.consume("SonyEricssonWT19i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia E", true);
            if (context.consume("SonyEricssonR800i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Play", true);
            if (context.consume("SonyEricssonST27i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Go", true);
            if (context.consume("SonyEricssonE10a", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia X10 Mini", true);
            if (context.consume("SonyEricssonX10i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia X10", true);
            if (context.consume("SonyEricssonX10a", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia X10a", true);
            if (context.consume("SonyEricssonSO-01B", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia X10", true);
            if (context.consume("SonyEricssonR800a", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Play 4G", true);
            if (context.consume("SonyEricssonR800x", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Play", true);
            if (context.consume("SonyEricssonE15a", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia X8", true);
            if (context.consume("SonyEricssonE15i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia X8", true);
            if (context.consume("SonyEricssonMK16i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Pro", true);
            if (context.consume("SonyEricssonLT15i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Arc", true);
            if (context.consume("SonyEricssonST18i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Ray", true);
            if (context.consume("SonyEricssonST18a", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Ray", true);
            if (context.consume("SonyEricssonSK17i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Mini Pro", true);
            if (context.consume("SonyEricssonLT26i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia S", true);
            if (context.consume("SonyEricssonST25i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia U", true);
            if (context.consume("SonyEricssonLT18i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Arc S", true);
            if (context.consume("SO-01C", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia arc", true);
            if (context.consume("SGP321", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.SONY,"Xperia Tablet Z", true);
            if (context.consume("C6603", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Z", true);

            if (context.consume("LT26i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia S", true);
            if (context.consume("LT26i", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia S", true);
            if (context.consume("SGP611 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Z3", true);
            if (context.consume("D6503 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Z2", true);
            if (context.consume("C6903 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Z1", true);
            if (context.consume("D5503 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Z1", true);
            if (context.consume("C1904 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia M", true);
            if (context.consume("C6833 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Z Ultra", true);
            if (context.consume("C5303 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia SP", true);
            if (context.consume("D58[03]3 .*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Z3 Compact", true);
            if (context.consume("D66(03|16|43|53) .*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Z3", true);
            if (context.consume("D6633 .*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SONY,"Xperia Z3 Dual", true);

            // Sharp
            if (context.consume("SBM106SH", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SHARP,"SBM106SH", true);

            // HTC
            if (context.consume("Sprint APX515CKT", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Evo 3D X515xkt", true);
            if (context.consume("Sprint APA9292KT", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Evo 4G", true);
            if (context.consume("Sprint APA7373KT", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"EVO Shift 4G", true);
            if (context.consume("EVO ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Evo 4G", true);
            if (context.consume("HTC Inspire 4G ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Inspire 4G", true);
            if (context.consume("HTC_Runnymede ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Runnymede", true);

            if (context.consume("ADR6300 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Droid Incredible", true);
            if (context.consume("(USCC)?ADR6325(US)? .*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Merge", true);
            if (context.consume("pcdadr6350 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"ADR6350", true);
            if (context.consume("PC36100 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"One XL", true);
            if (context.consume("IncredibleS_S710e", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Incredible S", true);
            if (context.consume("Incredible S ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Incredible S", true);
            if (context.consume("HTL21", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"J Butterfly", true);
            if (context.consume("(HTC[ _])?EVO( )?3D[ _]X515m.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Evo 3D X515m", true);
            if (context.consume("(HTC_)?Amaze_4G.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Amaze 4G", true);
            if (context.getUA().indexOf("HTC")>0) {
                if (context.consume("HTC_Flyer_P512_NA ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Flyer", true);
                if (context.consume("HTC[_ ]Dream .*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Dream", true);
                if (context.consume("HTC_S510b ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Rhyme", true);
                if (context.consume("HTC Liberty ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Liberty/Aria/Intruder/A6366", true);
                if (context.consume("HTC_WildfireS", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Wildfire S (Marvel)", true);
                if (context.consume("HTCA510e/1.0", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"WildFire", true);
                if (context.consume("HTCA510e", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Wildfire (Buzz)", true);
                if (context.consume("HTC[_ ]Sensation[_ ]4G.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Sensation 4G", true);
                if (context.consume("HTC_PH39100/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Vivid", true);
                if (context.consume("HTC_T120C ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"One V", true);
                if (context.consume("HTC_One_X", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"One X", true);
                if (context.consume("HTC EVA_UL", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"One X Evita", true);
                if (context.consume("HTC_One_S", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"One S", true);
                if (context.consume("HTC_DesireS_S510e", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire S", true);
                if (context.consume("HTC/DesireS/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire S", true);
                if (context.consume("HTC_DesireHD_A9191", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire HD", true);
                if (context.consume("HTC_C715c", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"EVO Design 4G", true);
                if (context.consume("HTC Sensation Z710e", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Sensation Z710e", true);
                if (context.consume("HTC Glacier", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Glacier", true);
                if (context.consume("HTC_Rhyme_S510b", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Rhyme", true);
                if (context.consume("HTC/WildfireS/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Wildfire S", true);
                if (context.consume("HTC-PG762 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Wildfire S", true);
                if (context.consume("HTC/Sensation/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Sensation", true);
                if (context.consume("HTC_SensationXL_Beats-", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Sensation XL Beats", true);
                if (context.consume("HTC One X", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"One X", true);
                if (context.consume("HTC Click-", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Click/Tattoo", true);
                if (context.consume("HTC Incredible S", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Incredible S", true);
                if (context.consume("HTC Desire HD", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire HD", true);
                if (context.consume("HTC HD2", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"HD2/Leo", true);
                if (context.consume("HTC[_ ]Wildfire[-_ ].*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Wildfire", true);
                if (context.consume("HTC Desire C", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire C", true);
                if (context.consume("HTC_DesireZ_", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire Z", true);
                if (context.consume("HTC-A7275", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire Z", true);
                if (context.consume("HTC D816v ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire 816", true);
                if (context.consume("HTC D816h ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire 816", true);
                if (context.consume("HTC Desire 816", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire 816", true);
                if (context.consume("HTC Desire ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire", true);
                if (context.consume("HTC_Desire", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire", true);
                if (context.consume("HTC Hero ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Hero", true);
                if (context.consume("HTC Vision ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire Z", true);
                if (context.consume("HTC Legend ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Legend", true);
                if (context.consume("HTC One S ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"One S", true);
                if (context.consume("HTC[_ ]One[_ ]V .*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"One V", true);
                if (context.consume("HTC Bravo ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Desire", true);
                if (context.consume("HTC Salsa C510b ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Salsa", true);
                if (context.consume("HTC One Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"One", true);
                if (context.consume("HTCONE Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"One", true);
                if (context.consume("HTC_One Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"One", true);
                if (context.consume("HTC-A9192/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                    context.consume("Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
                    return new Device(arm,DeviceType.PHONE,Brand.HTC,"Inspire 4G", true);
                }
                if (context.consume("HTC-A6366/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                    context.consume("Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
                    return new Device(arm,DeviceType.PHONE,Brand.HTC,"Liberty/Aria/Intruder/A6366", true);
                }


            }
            if (context.consume("ADR6350 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Droid Incredible 2", true);
            if (context.consume("A6277 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                context.consume("APA6277KT", MatchingType.EQUALS, MatchingRegion.REGULAR);
                return new Device(arm,DeviceType.PHONE,Brand.HTC,"Hero", true);
            }

            if (context.consume("HTC Magic ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.HTC,"Magic", true);
            // LG
            {
                Device res = null;
                if (context.consume("LG-MS770 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Motion 4G");
                if (context.consume("Optimus 2X", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus 2X");
                if (context.consume("LGMS323 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus L70");
                if (context.consume("LG-V500 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.TABLET,Brand.LG,"G Pad 8.3");
                if (context.consume("Vortex ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Vortex");
                if (context.consume("LG-L[GS]855.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Marquee");
                if (context.consume("LG-LU6500", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus Q2");
                if (context.consume("LGL55C Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus Q");
                if (context.consume("LG-LS840 Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Viper");
                if (context.consume("LG-MS690 Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus M");
                if (context.consume("LG-MS695 Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus M+");

                if (context.consume("LG-P350", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus Me");
                if (context.consume("LG-P500", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus One");
                if (context.consume("LG-P509", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus T");
                if (context.consume("LG-P700", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus L7");
                if (context.consume("LG-P715", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus L7 II");
                if (context.consume("LG-P870", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Escape");
                if (context.consume("LG-P880", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus 4X HD");
                if (context.consume("LG-P920", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus 3D");
                if (context.consume("LG-P925", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Thrill 4G");
                if (context.consume("LG-P970", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus Black");
                if (context.consume("LG-P990", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus 2X");
                if (context.consume("LG-D618", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"G2 Mini");
                if (context.consume("LG-P999", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"G2x");
                if (context.consume("LG-US670", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus U");
                if (context.consume("LG-GT540", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus GT540");
                if (context.consume("LG-E400", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus L3");
                if (context.consume("LG-LS720",MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus F3");
                if (context.consume("LG-E739", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"myTouch");
                if (context.consume("LG-C800 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"myTouch Q");
                if (context.consume("LG-VS700", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Enlighten");
                if (context.consume("LG-VM696", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus Elite");
                if (context.consume("VS415PP", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus Zone 2");
                if (context.consume("LG Eve", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"Eve");
                if (context.consume("VS980 4G ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"G2");
                if (context.consume("LG-VS980 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) res = new Device(arm,DeviceType.PHONE,Brand.LG,"G2");

                if (res != null) {
                    context.consume("MMS/LG-Android-MMS", MatchingType.BEGINS, MatchingRegion.REGULAR);
                    context.consume("Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);
                    res.setTouch(true);
                    return res;
                }
            }

            // Google branded
            if (context.consume("Galaxy Nexus", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.GOOGLE, Brand.SAMSUNG,"Galaxy Nexus", true);
            if (context.consume("Nexus S", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.GOOGLE, Brand.SAMSUNG,"Nexus S", true);
            if (context.consume("Nexus One", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.GOOGLE, Brand.HTC,"Nexus One", true);
            if (context.consume("Nexus 7", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.GOOGLE, Brand.ASUS,"Nexus 7", true);
            if (context.consume("Nexus 4", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.GOOGLE, Brand.LG,"Nexus 4", true);
            if (context.consume("Nexus 5", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.GOOGLE, Brand.LG,"Nexus 5", true);
            if (context.consume("Nexus 9", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.GOOGLE, Brand.HTC,"Nexus 10", true);
            if (context.consume("Nexus 10", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.GOOGLE, Brand.SAMSUNG,"Nexus 10", true);

            // Motorola
            if (context.contains("motorola", MatchingType.EQUALS, MatchingRegion.REGULAR) && context.contains("[0-9]+X[0-9]+", MatchingType.REGEXP, MatchingRegion.REGULAR)) {
                context.consume("motorola", MatchingType.EQUALS, MatchingRegion.REGULAR);
                context.consume("[0-9]+X[0-9]+", MatchingType.REGEXP, MatchingRegion.REGULAR);

                if (context.consume("WX445", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                    context.consume("WX445", MatchingType.EQUALS, MatchingRegion.REGULAR);
                    return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Citrus", true);
                }
                if (context.consume("DROIDX Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                    context.consume("DROIDX", MatchingType.EQUALS, MatchingRegion.REGULAR);
                    return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid X", true);
                }
            }
            if (context.consume("MZ60[14].*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.MOTOROLA,"Xoom", true);
            if (context.consume("MB865 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Atrix 2", true);
            if (context.consume("MB860 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Atrix", true);
            if (context.consume("MB525 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                context.consume("MOT-MB525", MatchingType.BEGINS, MatchingRegion.REGULAR);
                return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"DEFY", true);
            }
            if (context.consume("MB526 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"DEFY+", true);

            if (context.consume("DROID2", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid 2", true);
            if (context.consume("DROID3", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid 3", true);
            if (context.consume("DROID4 4G", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid 4", true);
            if (context.consume("DROID RAZR 4G", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid Razr 4G", true);
            if (context.consume("DROID RAZR HD", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid Razr HD", true);
            if (context.consume("DROID RAZR Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid Razr", true);
            if (context.consume("Droid", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid", true);
            if (context.consume("DROID BIONIC 4G", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid Bionic 4G", true);
            if (context.consume("DROID BIONIC", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid Bionic", true);
            if (context.consume("DROID P[Rr][Oo] .*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid Pro", true);
            if (context.consume("DROIDX ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid X", true);
            if (context.consume("DROID X2 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid X2", true);
            if (context.consume("MOTWX435KT", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Triumph", true);
            if (context.consume("XT1254 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Droid Turbo (Quark)", true);
            if (context.consume("XT1058 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Moto X", true);
            if (context.consume("XT1097 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Moto X XT1097", true);
            if (context.consume("XT890 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(atom,DeviceType.PHONE,Brand.MOTOROLA,"RAZR i", true);
            if (context.consume("XT321 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.MOTOROLA,"Defy Mini", true);

            // Asus
            if (context.consume("ASUS Transformer Pad TF700T", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.ASUS,"Transformer Pad Infinity", true);
            if (context.consume("ASUS Transformer Pad TF300T", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.ASUS,"Transformer Pad TF300T", true);
            if (context.consume("Transformer TF101", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.ASUS,"Eee Pad Transformer", true);
            if (context.consume("Transformer Prime TF201", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.ASUS,"Eee Pad Transformer Prime", true);
            if (context.consume("K014 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device("Intel Bay Trail",DeviceType.TABLET,Brand.ASUS,"K014", true);
            if (context.consume("ME173X ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.ASUS,"MeMO Pad HD7", true);

            // Acer
            if (context.consume("A700", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.ACER,"Iconia Tab A700", true);
            if (context.consume("A1-810", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.ACER,"Iconia A1-810", true);
            if (context.consume("A1-840", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.ACER,"Iconia Tab 8", true);

            // Lenovo
            if (context.consume("Lenovo P700", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.LENOVO,"P700", true);
            if (context.consume("(Lenovo )?K900 .*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(atom,DeviceType.PHONE,Brand.LENOVO,"K900", true);
            if (context.consume("IdeaTabA1000-", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.LENOVO,"IdeaTab A100", true);
            if (context.consume("Lenovo A889 Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.LENOVO,"A889", true);

            // Amazon
            if (isKindle(context,true)) {
                if (context.consume("KFTT", MatchingType.BEGINS, MatchingRegion.CONSUMED)) return new Device(arm,DeviceType.TABLET,Brand.AMAZON,"Kindle Fire", true);
                if (context.consume("KFJWI", MatchingType.BEGINS, MatchingRegion.CONSUMED)) return new Device(arm,DeviceType.TABLET,Brand.AMAZON,"Kindle Fire HD 8.9", true);
                if (context.consume("KFOTE", MatchingType.BEGINS, MatchingRegion.CONSUMED)) return new Device(arm,DeviceType.TABLET,Brand.AMAZON,"Kindle Fire (2nd gen)", true);
                if (context.consume("KFOT ", MatchingType.BEGINS, MatchingRegion.CONSUMED)) return new Device(arm,DeviceType.TABLET,Brand.AMAZON,"Kindle Fire 7", true);
                if (context.consume("KFTHWI", MatchingType.BEGINS, MatchingRegion.CONSUMED)) return new Device(arm,DeviceType.TABLET,Brand.AMAZON,"Kindle Fire HDX 7 (3rd gen)", true);
            }

            // Toshiba
            if (context.consume("IS04", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.TOSHIBA,"Regza IS04", true);
            if (context.consume("AT300 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.TOSHIBA,"AT300", true);
            if (context.consume("AT10-A ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.TOSHIBA,"Excite Pure", true);

            // Other Android stuff
            if (context.consume("MI 3W Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.XIAOMI,"Mi3", true);
            if (context.consume("ADM712HC ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.ODYS,"Neo X7", true);
            if (context.consume("WAX ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.WIKO,"Wax", true);
            if (context.consume("JIMMY ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.WIKO,"Jimmy", true);
            if (context.consume("CINK PEAX ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.WIKO,"Cink Peax", true);
            if (context.consume("CINK FIVE Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.WIKO,"Cink Five", true);
            if (context.consume("Archos 50 Helium 4G ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.ARCHOS,"50 Helium", true);
            if (context.consume("Archos 101c Neon Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.ARCHOS,"101c Neon", true);
            if (context.consume("Connect 501 Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.BOULANGER,"Connect 501", true);
            if (context.consume("IM-A850L ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.PANTECH,"Vega R3", true);
            if (context.consume("C351A ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.POSHMOBILE,"Pegasus Plus", true);
            if (context.consume("CUBOT X6 ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.CUBOT,"X6", true);
            if (context.consume("C6750 Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.KYOCERA,"Hydro Elite", true);
            if (context.consume("Event Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.KYOCERA,"Event", true);
            if (context.consume("E500 Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.LOGICOM,"E500", true);
            if (context.consume("PHS-601 Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.CONDOR,"C8", true);
            if (context.consume("A0001 Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.ONEPLUS,"One", true);
            if (context.consume("Tabra QAV801 Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.UNKNOWN,"QAV 801", true);
            if (context.consume("ALCATEL ONE TOUCH 7041D Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.ALCATEL,"OneTouch Pop C7", true);
            if (context.consume("M6 Build/", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(atom,DeviceType.TABLET,Brand.YUANDAO,"M6", true);
            if (context.consume("M-MP715I ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(atom,DeviceType.TABLET,Brand.MEDIACOM,"Smart Pad", true);


            // Generic Android
            if (context.consume("Tablet", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device("",DeviceType.TABLET,Brand.UNKNOWN,"Unknown", true);
            return new Device("",DeviceType.UNKNOWN_MOBILE,Brand.UNKNOWN,"Unknown", true);
        }
        if (o.getFamily() == OSFamily.LINUX) {
            if (context.consume("Transformer TF101", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.ASUS,"Eee Pad Transformer", true);
        }

        if (b.getFamily() == BrowserFamily.NETFRONT) {
            String device = context.getcRegion("(SAMSUNG-)?GT-([SB][0-9][0-9][0-9][0-9])/.*", MatchingRegion.REGULAR, 2);
            if (device != null) {
                return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,device);
            }
            //if (context.consume("(SAMSUNG-)?GT-(S3310/.*", MatchingType.REGEXP, MatchingRegion.REGULAR)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"S3310");
        }

        // Apple
        if (o.getFamily() == OSFamily.IOS) {
            if (context.consume("iPod", MatchingType.EQUALS, MatchingRegion.PARENTHESIS) ||
                    context.consume("device", MatchingType.EQUALS, MatchingRegion.PARENTHESIS) || // First gen ipod touch
                    context.consume("iPod touch", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                String dev = "iPod Touch";
                if (context.getUA().indexOf("iPod2,1")>-1) {
                    context.consume("iPod2,1", MatchingType.REGEXP, MatchingRegion.BOTH);
                    dev = "iPod Touch (2nd gen)";
                }


                return new Device(arm, DeviceType.PHONE,Brand.APPLE,dev,true);
            }
            if (context.consume("iPad", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm, DeviceType.TABLET,Brand.APPLE,"iPad",true);
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
                    else
                        context.consume("iPhoneUnknown", MatchingType.BEGINS, MatchingRegion.PARENTHESIS);

                }
                return new Device(arm, DeviceType.PHONE,Brand.APPLE,dev,true);
            }
        }

        // BlackBerry
        if (o.getVendor() == Brand.RIM) {
            context.consume("VendorID/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            if (context.consume("BlackBerry9000/", MatchingType.BEGINS, MatchingRegion.CONSUMED)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Bold 9000",true);
            if (context.consume("BlackBerry9300/", MatchingType.BEGINS, MatchingRegion.CONSUMED)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Curve 9300",true);
            if (context.consume("BlackBerry9630/", MatchingType.BEGINS, MatchingRegion.CONSUMED)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Tour 9630",true);
            if (context.consume("BlackBerry9700/", MatchingType.BEGINS, MatchingRegion.CONSUMED)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Bold 9700",true);
            if (context.consume("BlackBerry8520/", MatchingType.BEGINS, MatchingRegion.CONSUMED)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Curve 8520",true);
            if (context.consume("BlackBerry8530/", MatchingType.BEGINS, MatchingRegion.CONSUMED)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Curve 8530",true);
            if (context.consume("BlackBerry 9650", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Bold 9650",true);
            if (context.consume("BlackBerry 9670", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Style 9670",true);
            if (context.consume("BlackBerry 9700", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Bold 9700",true);
            if (context.consume("BlackBerry 9300", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Curve 9300",true);
            if (context.consume("BlackBerry 9790", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Bold 9790",true);
            if (context.consume("BlackBerry 9780", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Bold 9780",true);
            if (context.consume("BlackBerry 9330", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Curve 3G 9330",true);
            if (context.consume("BlackBerry 9320", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Curve 9320",true);
            if (context.consume("BlackBerry 9380", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Curve 9380",true);
            if (context.consume("BlackBerry 9360", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Curve 9360",true);
            if (context.consume("BlackBerry 9930", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Bold 9930",true);
            if (context.consume("BlackBerry 9900", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Bold 9900",true);
            if (context.consume("BlackBerry 9220", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Curve 9220",true);
            if (context.consume("BlackBerry 9800", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Torch 9800",true);
            if (context.consume("BlackBerry 9860", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Torch 9860",true);
            if (context.consume("BlackBerry 9810", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.RIM,"BlackBerry Torch 9810",true);
            if (context.consume("PlayBook", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.TABLET,Brand.RIM,"PlayBook",true);
            return new Device(arm,DeviceType.UNKNOWN_MOBILE,Brand.RIM,"",true);
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
        if (context.consume("Xbox One", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            context.consume("Xbox", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            return new Device("AMD x86-64",DeviceType.CONSOLE,Brand.MICROSOFT,"Xbox One");
        }
        if (context.consume("Xbox", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            if (context.getUA().contains("MSIE 9")) return new Device("PowerPC",DeviceType.CONSOLE,Brand.MICROSOFT,"Xbox 360");
            //if (context.getUA().contains("MSIE 7")) return new Device("x86 (PIII)",DeviceType.CONSOLE,Brand.MICROSOFT,"Xbox"); No browser on original Xbox ?
        }
        if (context.consume("PlayStation Vita", MatchingType.BEGINS, MatchingRegion.CONSUMED)) return new Device(arm,DeviceType.CONSOLE,Brand.SONY,"PlayStation Vita ");
        if (context.consume("PLAYSTATION 3", MatchingType.BEGINS, MatchingRegion.CONSUMED)) return new Device("Cell",DeviceType.CONSOLE,Brand.SONY,"PlayStation 3");
        if (context.consume("PlayStation Portable", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
            context.consume("PSP", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            return new Device("MIPS",DeviceType.CONSOLE,Brand.SONY,"PlayStation Portable");
        }

        // WinMo
        if (o.getFamily() == OSFamily.WINDOWS_MOBILE || o.getFamily() == OSFamily.WINDOWS_NT) {
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

            if (o.getVersion().equals("CE")) {
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

                if (context.consume("UTStar-XV6175.1", MatchingType.BEGINS, MatchingRegion.REGULAR)) {
                    return new Device(arm,DeviceType.PHONE,Brand.UTSTARCOM,"XV6175");
                }

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
                    return new Device(arm,DeviceType.PHONE,Brand.SONY,"Aspen M1i",true);

                if (context.consume("Touch_HD_T8282", MatchingType.BEGINS, MatchingRegion.PARENTHESIS))
                    return new Device(arm,DeviceType.PHONE,Brand.HTC,"Focus Flash",true);


                if (context.getcNextTokens(new Matcher[] {new Matcher("HTC",MatchingType.EQUALS),
                    new Matcher("mwp6985",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null ||
                context.getcNextTokens(new Matcher[] {new Matcher("HTC",MatchingType.EQUALS),
                                           new Matcher("7 Trophy",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.HTC,"7 Trophy",true);
                if (context.getcNextTokens(new Matcher[] {new Matcher("HTC",MatchingType.EQUALS),
                    new Matcher("T8697",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null ||
                context.getcNextTokens(new Matcher[] {new Matcher("HTC",MatchingType.EQUALS),
                                           new Matcher("7 Mozart",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.HTC,"7 Mozart",true);
                if (context.getcNextTokens(new Matcher[] {new Matcher("HTC",MatchingType.EQUALS),
                    new Matcher("Radar",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.HTC,"Radar",true);
                if (context.getcNextTokens(new Matcher[] {new Matcher("HTC",MatchingType.EQUALS),
                    new Matcher("T8788",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.HTC,"7 Surround",true);
                if (context.getcNextTokens(new Matcher[] {new Matcher("HTC",MatchingType.EQUALS),
                    new Matcher("HD7 T9292",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.HTC,"HD7 T9292",true);
                if (context.getcNextTokens(new Matcher[] {new Matcher("HTC",MatchingType.EQUALS),
                    new Matcher("7 Pro",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.HTC,"7 Pro",true);
                if (context.getcNextTokens(new Matcher[] {new Matcher("HTC",MatchingType.EQUALS),
                    new Matcher("TITAN",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.HTC,"Titan",true);
                if (context.getcNextTokens(new Matcher[] {new Matcher("HTC",MatchingType.EQUALS),
                    new Matcher("HD7",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.HTC,"Schubert (HD7)",true);
                if (context.contains("Windows Phone 8X by HTC",MatchingType.EQUALS,MatchingRegion.CONSUMED) &&
                        context.consume("HTC",MatchingType.EQUALS,MatchingRegion.PARENTHESIS))
                    return new Device(arm,DeviceType.PHONE,Brand.HTC,"8X",true);

                if (context.consume("Lumia 1520",MatchingType.EQUALS, MatchingRegion.PARENTHESIS))
                    return new Device(arm,DeviceType.PHONE,Brand.NOKIA,"Lumia 1520",true);
                if (context.consume("Lumia 925",MatchingType.EQUALS, MatchingRegion.PARENTHESIS))
                    return new Device(arm,DeviceType.PHONE,Brand.NOKIA,"Lumia 925",true);
                if ((vers=context.getcNextTokens(new Matcher[] {new Matcher("NOKIA",MatchingType.EQUALS),
                    new Matcher("Lumia ",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS))!=null)
                return new Device(arm,DeviceType.PHONE,Brand.NOKIA,vers[1],true);
                if ((vers=context.getcNextTokens(new Matcher[] {new Matcher("Microsoft",MatchingType.EQUALS),
                    new Matcher("Lumia ",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS))!=null)
                return new Device(arm,DeviceType.PHONE,Brand.MICROSOFT,vers[1],true);

                if (context.getcNextTokens(new Matcher[] {new Matcher("SAMSUNG",MatchingType.EQUALS),
                    new Matcher("SGH-i917",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Focus",true);
                if (context.getcNextTokens(new Matcher[] {new Matcher("SAMSUNG",MatchingType.EQUALS),
                    new Matcher("SGH-i677",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Focus Flash",true);
                if (context.getcNextTokens(new Matcher[] {new Matcher("SAMSUNG",MatchingType.EQUALS),
                    new Matcher("OMNIA7",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Omnia 7",true);

                if (context.getcNextTokens(new Matcher[] {new Matcher("LG",MatchingType.EQUALS),
                    new Matcher("LG-C900",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus 7Q / Quantum",true);
                if (context.getcNextTokens(new Matcher[] {new Matcher("LG",MatchingType.EQUALS),
                    new Matcher("LG-E900",MatchingType.BEGINS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.LG,"Optimus 7",true);

                if (context.getcNextTokens(new Matcher[] {new Matcher("Acer",MatchingType.EQUALS),
                    new Matcher("Allegro",MatchingType.EQUALS)
                }, MatchingRegion.PARENTHESIS)!=null)
                return new Device(arm,DeviceType.PHONE,Brand.ACER,"Allegro",true);


                if (context.consume("Asus;Galaxy6",MatchingType.EQUALS, MatchingRegion.REGULAR))
                    return new Device(arm,DeviceType.PHONE,Brand.ASUS,"Galaxy 6");
                if (context.consume("garmin-asus-Nuvifone",MatchingType.BEGINS, MatchingRegion.PARENTHESIS))
                    return new Device(arm,DeviceType.PHONE,Brand.GARMIN,Brand.ASUS,"Nuvifone");

            }
            String arch = "";
            if (context.contains("ARM", MatchingType.EQUALS, MatchingRegion.CONSUMED)) {
                arch += "ARM";
            }

            if (o.getFamily() == OSFamily.WINDOWS_MOBILE) return new Device(arch,DeviceType.UNKNOWN_MOBILE,Brand.UNKNOWN,"");
        }



        // Bada
        if (o.getFamily() == OSFamily.BADA) {
            if (context.contains("SAMSUNG[ -]GT-.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS) ||
                    context.contains("GT-", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                if (context.consume("(SAMSUNG[ -])?GT-S5380.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Wave Y",true);
                if (context.consume("(SAMSUNG[ -])?GT-S8500.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Wave",true);
                if (context.consume("(SAMSUNG[ -])?GT-S8530.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Wave 2",true);
                if (context.consume("(SAMSUNG[ -])?GT-S5750.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Wave 575",true);
                if (context.consume("(SAMSUNG[ -])?GT-S5253.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Wave 525",true);
                if (context.consume("(SAMSUNG[ -])?GT-S7230.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Wave 723",true);
                if (context.consume("(SAMSUNG[ -])?GT-S8600.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Wave 3",true);
                if (context.consume("(SAMSUNG[ -])?GT-S5780.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Wave 578",true);
                if (context.consume("(SAMSUNG[ -])?GT-S5330.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(arm,DeviceType.PHONE,Brand.SAMSUNG,"Wave 533 / Wave 2 Pro",true);
            }
        }
        // Other samsung OS
        if (context.getUA().startsWith("SAMSUNG-GT-") || context.getUA().startsWith("SAMSUNG-SGH-") || context.getUA().startsWith("samsung-gt") || context.contains("SPH-M[0-9]{3}", MatchingType.REGEXP, MatchingRegion.BOTH)) {
            Device device = new Device(arm, DeviceType.PHONE, Brand.SAMSUNG, "");
            if (context.consume("SAMSUNG-GT-S5263/", MatchingType.BEGINS, MatchingRegion.REGULAR)) device.setDevice("Star II");
            if (context.consume("SAMSUNG-GT-S5230/", MatchingType.BEGINS, MatchingRegion.REGULAR)) device.setDevice("Player One");
            if (context.consume("SPH-M810", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) device.setDevice("Instinct Mini (S30)");
            if (context.consume("SPH-M800", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) device.setDevice("Instinct");
            if (context.consume("SPH-M570", MatchingType.EQUALS, MatchingRegion.REGULAR)) device.setDevice("Restore");
            if (context.consume("samsung-gt-s5350/", MatchingType.BEGINS, MatchingRegion.REGULAR)) device.setDevice("Shark");
            if (context.consume("SAMSUNG-SGH-E250/",MatchingType.BEGINS, MatchingRegion.REGULAR)) device.setDevice("SGH E250");
            if (device.getDevice().length()>0) {
                context.consume("SAMSUNG", MatchingType.EQUALSIGNORECASE, MatchingRegion.PARENTHESIS);
                if (o.getFamily() == OSFamily.UNKNOWN) {
                    o.setFamily(OSFamily.OTHER);
                    o.setVendor(Brand.SAMSUNG);
                    o.setDescription("Proprietary OS");
                }
                if (b.getFamily() == BrowserFamily.UNKNOWN && (ver = context.getcVersionAfterPattern("Dolfin/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
                    b.setDescription("Dolfin " + ver);
                    b.setFamily(BrowserFamily.OTHER);
                    b.setRenderingEngine(new RenderingEngine(Brand.SAMSUNG, RenderingEngineFamily.OTHER, ver, 2));
                    b.setVendor(Brand.SAMSUNG);
                } else if (b.getFamily() == BrowserFamily.UNKNOWN && (ver = context.getcVersionAfterPattern("Jasmine/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
                    // Not so sure this is actually a web browser...
                    b.setDescription("Jasmine " + ver);
                    b.setFamily(BrowserFamily.OTHER);
                    b.setRenderingEngine(RenderingEngine.getUnknown());
                    b.setVendor(Brand.SAMSUNG);
                } else if (b.getFamily() == BrowserFamily.UNKNOWN && (ver = context.getcVersionAfterPattern("Browser",  MatchingType.BEGINS, MatchingRegion.REGULAR, 2))!=null) {
                    // Not so sure this is actually a web browser...
                    b.setDescription("Browser " + ver);
                    b.setFamily(BrowserFamily.OTHER);
                    b.setRenderingEngine(RenderingEngine.getUnknown());
                    b.setVendor(Brand.SAMSUNG);
                } else if (b.getFamily() == BrowserFamily.UNKNOWN && (ver = context.getcVersionAfterPattern("TELECA-/",  MatchingType.BEGINS, MatchingRegion.REGULAR, 2))!=null) {
                    b.setDescription("Teleca");
                    b.setFullVersionOneShot(ver, 2);
                    b.setFamily(BrowserFamily.OTHER);
                    b.setRenderingEngine(RenderingEngine.getOther(Brand.OBIGO));
                    b.setVendor(Brand.OBIGO);
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
                b.setFamily(BrowserFamily.OPERA);
                b.setDescription("Opera");
                b.setFullVersionOneShot(ver, 2);
                b.setRenderingEngine(new RenderingEngine(Brand.OPERA, RenderingEngineFamily.PRESTO, ver, 2));
                b.setVendor(Brand.OPERA);
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
        if (o.getFamily() == OSFamily.CHROMEOS) {
            if ((ver = context.getcVersionAfterPattern("CrOS", MatchingType.BEGINS, MatchingRegion.CONSUMED)) != null) {
                if (ver.contains(" "))
                    return new Device(ver.split(" ")[0],DeviceType.COMPUTER,Brand.UNKNOWN,"");
            }
        }
        if (o.getFamily() == OSFamily.WINDOWS_NT) {
            String arch = "";
            DeviceType deviceType = DeviceType.COMPUTER;
            Brand brand = Brand.UNKNOWN;
            String device = "PC";
            boolean touch = false;

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
            if (context.contains("Windows NT 6\\.[23]", MatchingType.REGEXP, MatchingRegion.CONSUMED) &&
                    (context.contains("ARM", MatchingType.EQUALS, MatchingRegion.CONSUMED) || context.consume("ARM", MatchingType.EQUALS, MatchingRegion.PARENTHESIS))) {
                arch += " ARM";
            }
            if (context.contains("Windows NT 6\\.[23]", MatchingType.REGEXP, MatchingRegion.CONSUMED) &&
                    context.consume("Touch", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                touch = true;
            }
            if (context.consume("Tablet PC [1-2]\\.[07]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) {
                deviceType = DeviceType.TABLET;
            }

            Device deviceByManufacturer;
            while ((deviceByManufacturer= getWindowsDevice(context)) != null) {
                brand = deviceByManufacturer.getBrand();
                if (deviceByManufacturer.getDevice() != null && deviceByManufacturer.getDevice().length()>0) device = deviceByManufacturer.getDevice();
            }

            return new Device(arch.trim(),deviceType,brand,device,touch);
        }
        if (o.getFamily() == OSFamily.WINDOWS) {
            String arch = "Intel";
            if (context.consume("Win32", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) arch += " 32 bits";
            if (context.consume("AMD64", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) arch = "AMD 64 bits";
            return new Device(arch,DeviceType.COMPUTER,Brand.UNKNOWN,"PC");
        }

        if (o.getFamily() == OSFamily.MACOSX || o.getFamily() == OSFamily.MACOS) {
            if (context.contains("Intel Mac OS X", MatchingType.BEGINS, MatchingRegion.CONSUMED))
                return new Device("Intel",DeviceType.COMPUTER,Brand.APPLE,"Macintosh");
            if (context.contains("PPC Mac OS X", MatchingType.BEGINS, MatchingRegion.CONSUMED))
                return new Device("Power PC",DeviceType.COMPUTER,Brand.APPLE,"Macintosh");
            if (context.contains("Mac_PowerPC", MatchingType.BEGINS, MatchingRegion.CONSUMED))
                return new Device("Power PC",DeviceType.COMPUTER,Brand.APPLE,"Macintosh");
            if (context.consume("PPC", MatchingType.EQUALS, MatchingRegion.PARENTHESIS))
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

        if (o.getFamily() == OSFamily.LINUX) {
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
        if (o.getFamily() == OSFamily.BEOS) {
            if (context.contains("BeOS BeBox", MatchingType.EQUALS, MatchingRegion.CONSUMED)) return new Device("PowerPC",DeviceType.COMPUTER,Brand.BE,"BeBox");
        }

        if (o.getFamily() == OSFamily.BSD) {
            if (context.contains("(Free|Open)BSD ([0-9.]+-RELEASE )?i386", MatchingType.REGEXP, MatchingRegion.CONSUMED)) return new Device("i386",DeviceType.COMPUTER,Brand.UNKNOWN,"");
            if (context.contains("(Free|Open)BSD ([0-9.]+-RELEASE )?amd64", MatchingType.REGEXP, MatchingRegion.CONSUMED)) return new Device("AMD 64bits",DeviceType.COMPUTER,Brand.UNKNOWN,"");
        }

        if (o.getFamily() == OSFamily.UNIX && o.getDescription().equals("SunOS")) {
            if (context.contains("SunOS.*i86pc.*", MatchingType.REGEXP, MatchingRegion.CONSUMED)) return new Device("Intel x86",DeviceType.COMPUTER,Brand.UNKNOWN,"PC");
            if (context.contains(".*sun4u", MatchingType.REGEXP, MatchingRegion.CONSUMED)) return new Device("UltraSPARC", DeviceType.COMPUTER, Brand.SUN, "UltraSPARC");
            if (context.contains(".*sun4[mv]", MatchingType.REGEXP, MatchingRegion.CONSUMED)) return new Device("SPARC", DeviceType.COMPUTER, Brand.SUN, "SPARC");
        }

        // Fallbacks
        if (context.contains("Opera Mobi", MatchingType.BEGINS, MatchingRegion.CONSUMED) ||
                context.contains("Opera Mini", MatchingType.BEGINS, MatchingRegion.CONSUMED))
            return new Device("",DeviceType.UNKNOWN_MOBILE,Brand.UNKNOWN,"");

        if (o.getVendor() == Brand.NOKIA) {
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

    private static Device getWindowsDevice(UserAgentContext context) {
        if (context.consume("MAAR(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(null, DeviceType.UNKNOWN, Brand.ACER, "");
        if (context.consume("MDD[CRS](JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(null, DeviceType.UNKNOWN, Brand.DELL,"");
        if (context.consume("HP([ND]TDF|CMHP)(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(null, DeviceType.UNKNOWN, Brand.HP,"");
        if (context.consume("(CMN|CPD|CPN)TDF(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(null, DeviceType.UNKNOWN, Brand.COMPAQ,"");
        if (context.consume("MAAR(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(null, DeviceType.UNKNOWN, Brand.ACER,"");
        if (context.consume("(MASP|MASA|MASE|MASP)(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(null, DeviceType.UNKNOWN, Brand.SONY,"");
        if (context.consume("(MASM|SMJB)(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(null, DeviceType.UNKNOWN, Brand.SAMSUNG,"");
        if (context.consume("(NP06|NP07|NP08|NP09|ASU2|ASJB|MAAU)(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(null, DeviceType.UNKNOWN, Brand.ASUS,"");
        if (context.consume("(MAFS|FSJB)(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(null, DeviceType.UNKNOWN, Brand.FUJITSU,"");
        if (context.consume("(MALE|MALN|LCJB|LEN2|MALC)(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(null, DeviceType.UNKNOWN, Brand.LENOVO,"");
        if (context.consume("MAGW(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(null, DeviceType.UNKNOWN, Brand.GATEWAY,"");
        if (context.consume("MAMD(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(null, DeviceType.UNKNOWN, Brand.MEDION,"");
        if (context.consume("MANM(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(null, DeviceType.UNKNOWN, Brand.HYRICAN,"");
        if (context.consume("(MATM|MATP|TAJB|TNJB|MATB)(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(null, DeviceType.UNKNOWN, Brand.TOSHIBA,"");
        if (context.consume("(MAMI|MAM3)(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) return new Device(null, DeviceType.UNKNOWN, Brand.MSI,"");
        return null;
    }


    static Locale getLocaleSecondPass(UserAgentContext context, UserAgentDetectionResult result) {
        if (result.getBrowser().getFamily() == BrowserFamily.FIREFOX || result.getBrowser().getFamily() == BrowserFamily.OTHER_GECKO) {
            if (result.getOperatingSystem().getFamily() == OSFamily.MACOSX) {
                if (context.consume("ja-JP-mac", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                    return new Locale(Language.JA, Country.JP);
                }
            }
        }
        /*if (result.getOperatingSystem().getFamily() == OSFamily.WINDOWS_NT) {
          if (context.consume("BO[0-9]?IE[89](_v[0-9]+)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS) ||
              context.contains("msn OptimizedIE8", MatchingType.EQUALS, MatchingRegion.CONSUMED)) {
            Iterator<String> it = context.getParenTokensIterator();
            while (it.hasNext()) {
              String s = it.next();
              if (s.length() == 4) {
                Language l = LocaleHelper.getLanguage(s.substring(0,2));
                Country c = LocaleHelper.getCountry(s.substring(2,4));
                if (l != null && c != null) {
                  context.consume(s,MatchingType.EQUALS,MatchingRegion.PARENTHESIS);
                  return new Locale(l,c);
                }
              }
            }

          }
        }*/
        return result.getLocale();
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
            for (String l : langs) {
                String lang = l.trim();
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
            if (ok && langs.length>0) {
                return getLocale(langs[pos].trim(), context);
            }
        }

        return null;
    }

    static Locale getLocale(UserAgentContext context) {
        //String ua = context.getUA();
        //ua = ua.replaceAll("Windows CE","").replaceAll("Mac OS","").replaceAll("CPU OS","").replaceAll("iPhone OS","");
        //StringTokenizer stw = new StringTokenizer(ua," ;)(");
        Locale defaultLocale = new Locale();
        String toBeConsumedInPar = null;

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
        boolean afterMsnOpt = false;
        while (it.hasNext()) {
            String s = it.next();
            if (s.equals("MSN Optimized") || s.equals("msn OptimizedIE8") || s.matches("BO[0-9]?IE[89](_v[0-9]+)?")) {
                afterMsnOpt = true;
            } else {
                if (afterMsnOpt) {
                    if (s.length() == 2) {
                        Country c = LocaleHelper.getCountry(s);
                        if (c!=null) {
                            toBeConsumedInPar = s;
                            defaultLocale = new Locale(Language.UNKNOWN,c);
                        }
                    } else if (s.length()==4) {
                        Language l = LocaleHelper.getLanguage(s.substring(0,2));
                        Country c = LocaleHelper.getCountry(s.substring(2,4));
                        if (l != null && c != null) {
                            toBeConsumedInPar = s;
                            defaultLocale = new Locale(l,c);
                        }
                    }
                } else {
                    Locale l = getLocale(s,context);
                    if (l != null) {
                        context.consume(s,MatchingType.EQUALS,MatchingRegion.PARENTHESIS);
                        return l;
                    }
                    afterMsnOpt = false;
                }
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

        if (toBeConsumedInPar!=null)
            context.consume(toBeConsumedInPar, MatchingType.EQUALS,MatchingRegion.PARENTHESIS);
        return defaultLocale;
    }


    static void addExtensions(UserAgentContext context, UserAgentDetectionResult res) {
        UserAgentDetectionHelper.addExtensionsCommonForLibs(context, res);

        String ver;
        if (res.getOperatingSystem().getVendor() == Brand.SAMSUNG || res.getOperatingSystem().getFamily() == OSFamily.UNKNOWN) {
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
        if (res.getBrowser().getDescription().startsWith("Silk")) {
            if (context.consume("Silk-Accelerated=true",MatchingType.EQUALS, MatchingRegion.REGULAR)) {
                res.addExtension(new Extension("Silk-Accelerated",""));
            }
        }
        if (res.getBrowser().getDescription().startsWith("ELinks") || res.getBrowser().getDescription().startsWith("Lynx") || res.getBrowser().getDescription().startsWith("Links") || res.getOperatingSystem().getFamily() == OSFamily.WINDOWS_MOBILE) {
            String reso = context.getcToken("[0-9]+x[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
            if (reso != null)
                res.addExtension(new Extension("Resolution",reso));
        }
        if (res.getOperatingSystem().getFamily() == OSFamily.WINDOWS_MOBILE) {
            String reso = context.getcToken("[0-9]+[x\\*][0-9]+;?", MatchingType.REGEXP, MatchingRegion.BOTH);
            if (reso != null) {
                if (reso.endsWith(";")) reso = reso.substring(0, reso.length()-1);
                res.addExtension(new Extension("Resolution",reso));
            }
        }
        if (res.getBrowser().getFamily() == BrowserFamily.IE) {
            if (context.consume("DigExt",MatchingType.EQUALS, MatchingRegion.PARENTHESIS) || context.consume("MSIECrawler",  MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) {
                res.addExtension(new Extension("Offline Save")); // IE downloading for offline access
            }
            if ((ver = context.getcVersionAfterPattern("MathPlayer ",MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) != null) {
                res.addExtension(new Extension("Math Player", ver)); // Allow mathematics formulas display
            }
            if ((ver = context.getcVersionAfterPattern("chromeframe/",MatchingType.BEGINS, MatchingRegion.BOTH)) != null) {
                res.addExtension(new Extension("Chrome Frame",ver));
            }
        }
        if (res.getBrowser().getFamily() == BrowserFamily.IE || res.getBrowser().getFamily() == BrowserFamily.OTHER_TRIDENT) {
            if (context.consume("i-NavFourF",MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) {
                res.addExtension(new Extension("i-Nav","")); // Some auto-translation toolbar
            }
        }

        if (res.getBrowser().getFamily() == BrowserFamily.FIREFOX || res.getBrowser().getFamily() == BrowserFamily.OTHER_GECKO) {

            if (res.getBrowser().getDescription().startsWith("Thunderbird")) {
                if ((ver = context.getcVersionAfterPattern("ThunderBrowse/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) {
                    res.addExtension(new Extension("ThunderBrowse",ver));
                }
            }


            if ((ver = context.getcVersionAfterPattern("Navigator/",  MatchingType.BEGINS, MatchingRegion.BOTH))!=null) {
                res.addExtension(new Extension("Netscape Navigator",ver));
            }
            if ((ver = context.getcVersionAfterPattern("Glubble/",  MatchingType.BEGINS, MatchingRegion.REGULAR))!=null) { // Parental control filtering
                res.addExtension(new Extension("Glubble",ver));
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
        if (result.getBrowser().getFamily() == BrowserFamily.OTHER_TRIDENT || result.getBrowser().getFamily() == BrowserFamily.IE) {
            sep = " ";
            region = MatchingRegion.PARENTHESIS;
        } else {
            sep = "/";
            region = MatchingRegion.REGULAR;
        }
        String regexp = (ver == null) ? entity : (entity+sep+ver);
        return context.ignore(regexp, MatchingType.REGEXP, region);
    }

    static boolean consumeEntityFromIEAndFirefoxBuggy(String entity, String ver, UserAgentContext context, UserAgentDetectionResult result) {
        if (result.getBrowser().getFamily() == BrowserFamily.OTHER_TRIDENT || result.getBrowser().getFamily() == BrowserFamily.IE) {
            String regexp = entity+" "+ver;
            return context.ignore(regexp, MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        } else {
            return null != context.ignoreNextTokens(new Matcher[] {new Matcher(entity, MatchingType.REGEXP),
                       new Matcher(ver, MatchingType.REGEXP)
            },
            MatchingRegion.REGULAR);
        }
    }

    static void consumeRandomGarbage(UserAgentContext context, UserAgentDetectionResult result) {
        context.ignore("3gpp-gba", MatchingType.EQUALS, MatchingRegion.REGULAR); // Authentication protocol
        context.ignore("MALC", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); //Multiple Access Line Concentrator
        context.consume("U", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // "Secure" flag

        if (result.getOperatingSystem().getFamily() == OSFamily.WINDOWS_NT) {
            if (result.getBrowser().getFamily() == BrowserFamily.IE || result.getBrowser().getFamily() == BrowserFamily.OTHER_TRIDENT) {
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

        if (result.getOperatingSystem().getFamily() == OSFamily.ANDROID || result.getOperatingSystem().getFamily() == OSFamily.IOS) {
            context.ignore("MicroMessenger/", MatchingType.BEGINS, MatchingRegion.REGULAR); // No idea. Looks like real users.
        }

        if (result.getOperatingSystem().getFamily() == OSFamily.WINDOWS_NT || result.getOperatingSystem().getFamily() == OSFamily.WINDOWS) {
            while (context.consume(".NET CLR", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)) ;
            while (context.consume(".NET Client [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) ;
            context.ignore("HbTools [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Hotbar - kindof adware
        }


        if (result.getOperatingSystem().getFamily() == OSFamily.LINUX ||
                result.getOperatingSystem().getFamily() == OSFamily.UNIX ||
                result.getOperatingSystem().getFamily() == OSFamily.BSD ||
                result.getOperatingSystem().getFamily() == OSFamily.OTHER) {
            context.consume("X11", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // X11 windowing environment
            if (result.getOperatingSystem().getDescription().equals("SuSE")) {
                // Sometimes...
                context.consume("X11", MatchingType.EQUALS, MatchingRegion.REGULAR); // X11 windowing environment
            }
        }
        if (result.getBrowser().getFamily() == BrowserFamily.OTHER_TRIDENT || result.getBrowser().getFamily() == BrowserFamily.IE) {
            context.ignore("SiteKiosk [0-9\\.]+ Build [0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Some kiosk public computer browser whatever
            context.ignore("image_azv", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Dunno
            if (context.ignore("\\[xSP_2:[0-9a-f]+_[0-9]+\\]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)) { // Dunno
                while (context.ignore("\\[xSP_2:[0-9a-f]+_[0-9]+\\]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS));
                context.ignore("[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
            }
            context.ignore("APCPMS=", MatchingType.BEGINS, MatchingRegion.PARENTHESIS); // ?
            context.ignore("BO[0-9]?IE[89](_v[0-9]+)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Bing optimized bullshit
            context.ignore("msn OptimizedIE8", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Bing optimized bullshit
            context.ignore("Tucows", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Dunno
            context.ignore("TOB 6\\.[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Dunno
            context.ignore("Seekmo [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Adware http://www.wiki-security.com/wiki/Parasite/Seekmo/
            context.ignore("iebar", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Adware http://www.pandasecurity.com/homeusers/security-info/68498/IEBar/
            context.ignore("ShopperReports ", MatchingType.BEGINS, MatchingRegion.PARENTHESIS); // Adware http://www.spywareguide.com/spydet_1263_shopperreports.html
            while (context.ignore("IE7-01NET.COM", MatchingType.BEGINS, MatchingRegion.PARENTHESIS)); // Dunno
            context.ignore("RCP000\\.[0-9]{3}\\.[0-9]{5}/[a-f0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Dunno
            {   // Trojan: http://blog.armorize.com/2010/05/browser-helper-objects-infection-with.html and http://www.spambotsecurity.com/forum/viewtopic.php?f=43&t=1579
                context.ignore("SIMBAR=\\{[0-9ABCDEFabcdef\\-]+\\}", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
                context.ignore("SIMBAR Enabled", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
                context.ignore("SIMBAR=0", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            }
            context.ignore("WWTClient2", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // World Wide Telescope Client?
            context.ignore("TheFreeDictionary.com", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // What the heck is this?
            context.ignore("F-6\\.0SP[1-2]-200[0-9][0-9][0-9][0-9][0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Dunno
            while (context.ignore("SU [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)); // Dunno
            while (context.ignore("Sgrunt\\|V[0-9]{3}\\|[0-9]+\\|S-?[0-9]+\\|dial(no)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)); // Spyware http://forums.spybot.info/showthread.php?39512-Manual-Removal-Guide-for-Sgrunt
            context.ignore("snprtz(\\|[TS][0-9#]+(\\|[0-9#]+Service Pack [0-9#]+)?)?(\\|(dialno|isdn))?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Probably linked to Sgrunt because it is storongly correlated in my logs. Also: http://www.webmasterworld.com/forum11/3136.htm
            context.ignore("ADVPLUGIN\\|K[0-9]{3}\\|[0-9]+\\|S-?[0-9]+\\|dial(no)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Once again, correlated to Sgrunt. http://www.yac.mx/en/guides/adware/20141215-how-to-remove-advplugin-pup-by-yac-pc-cleaner.html
            if (context.ignore("EnergyPlugIn", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)) { // Once again, seems correlated to Sgrunt. Also linked to the "dial" part of the UA...
                context.ignore("dial", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            }
            context.ignore("E-nrgyPlus", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // dialer - malware  http://www.fbmsoftware.com/spyware-net/Application/E-nrgyplus/
            while (context.ignore("PeoplePal [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)); // Dunno. Doesn't look like a bot. Maybe http://www.paretologic.com/resources/definitions.aspx?remove=PeoplePal+Toolbar ?  This means adware.
            while (context.ignore("IWSS(25|31):[0-9A-Za-z/=\\+]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)); // Dunno, doesn't look like a bot. Maybe Trend Micro InterScan Web Security Suite
            while (context.ignore("IWSS:[0-9A-Za-z\\-/]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)); // Dunno, doesn't look like a bot. Maube Trend Micro InterScan Web Security Suite
            context.ignore("tnet.2007feb", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Dunno
            context.ignore("ibrytetoolbar_playbryte", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Dunno
            while (context.ignore("Qwest [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS)); // Dunno
            while (context.ignore("Qwest Communications", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)); // Gotta go with corporate installs
            context.ignore("yie6_SBC", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // IE Optimized for Yahoo. Gotta wonder what the fuck this could be... http://downloads.yahoo.com/internetexplorer/

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
            context.ignore("Ringo", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Dunno, usage pattern doesn't indicate a bot
            context.ignore("WinNT-PAI [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Trojan http://www.threatexpert.com/report.aspx?md5=72e15bf94e8cb6ea2fc8d0626774ddd2
            context.ignore("VB_juicypalace", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Dunno?
            context.ignore("UGDCFR [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Dunno
            context.ignore("eMusic DLM/4", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // eMusic Download Manager
            context.ignore("Badongo [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Badongo seems to be an app/add-on for music streaming
            context.ignore("SpamBlockerUtility [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Does look like it does more harm that good (Adware application from HotBar)
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

        if (result.getBrowser().getFamily() == BrowserFamily.OPERA && result.getDevice().getDeviceType() == DeviceType.PHONE) {
            context.ignore("BER2.2", MatchingType.EQUALS, MatchingRegion.REGULAR); // ?
            context.ignore("[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // ?
        }

        if (result.getBrowser().getFamily() == BrowserFamily.OTHER_GECKO || result.getBrowser().getFamily() == BrowserFamily.FIREFOX) {
            context.ignore("ayakawa PGU", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // http://forums.mozfr.org/viewtopic.php?f=24&t=64837 seems to indicate this is not a bot
            context.ignore("[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // No idea
            context.ignore("lolifox/", MatchingType.BEGINS, MatchingRegion.REGULAR); // Some bullshit addon to FF
            context.ignore("tete009 .*SSE[2]?.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Custom FF build http://www1.plala.or.jp/tete009/en-US/software.html
            context.ignore("tete009 .*MMX?.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Custom FF build
            context.ignore(";ShopperReports", MatchingType.BEGINS, MatchingRegion.REGULAR); // Adware http://www.spywareguide.com/spydet_1263_shopperreports.html
            context.ignore("FoxPlus", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Extension
            context.ignore("photobucket", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Extension
            context.ignore("FireShot /", MatchingType.BEGINS, MatchingRegion.REGULAR); // Extension
            if (null != context.ignoreNextTokens(new Matcher[] {new Matcher("FireShot", MatchingType.EQUALS),
                new Matcher("[\\.0-9]+", MatchingType.REGEXP)
            },
            MatchingRegion.REGULAR)) { // Extension
                context.consume("http://screenshot-program.com", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            }
            context.ignore("BFGod-Speedfox/", MatchingType.BEGINS, MatchingRegion.REGULAR); // Is this a browser? I cannot find anything on it anywhere.
            if (context.ignore("Me.dium/", MatchingType.BEGINS, MatchingRegion.REGULAR)) { // Social extension http://www.techvibes.com/company-directory/me.dium
                context.consume("http://me.dium.com", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            }
            context.ignore("Firefox musume", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Some sort of custom build
            if (context.ignore("compat/[0-9]+", MatchingType.REGEXP, MatchingRegion.REGULAR)) // Dunno
                while (context.consume("[0-9]+", MatchingType.REGEXP, MatchingRegion.REGULAR)) ;
            context.ignore("XF_mmhpset", MatchingType.EQUALS, MatchingRegion.REGULAR); // Dunno
            context.ignore("BT-lookingforgroup", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Dunno
            while (context.ignore("GendFox", MatchingType.EQUALS, MatchingRegion.BOTH)); // This indicates it's probably not a bot : http://forums.mozfr.org/viewtopic.php?t=59568&p=410453
            context.ignore("RTSE/[0-9\\.]+", MatchingType.REGEXP, MatchingRegion.REGULAR); // Dunno
            context.ignore("MultiZilla/", MatchingType.BEGINS, MatchingRegion.REGULAR); // Collection of FF extensions
            context.ignore("FirePHP/", MatchingType.BEGINS, MatchingRegion.REGULAR); // extension for developers
            context.ignore("FireShot/", MatchingType.BEGINS, MatchingRegion.REGULAR); // Screeshot extension for FF
            if (context.ignore("OneRiot/", MatchingType.BEGINS, MatchingRegion.REGULAR)) { // Social media crap
                context.consume("http://.*oneriot.*", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
            }
            context.ignore("UGA6PV", MatchingType.BEGINS, MatchingRegion.REGULAR);// This website would suggest this is operated by a human: http://forums.mozfr.org/viewtopic.php?t=66727&p=455964
            context.ignore("UGA6P/", MatchingType.BEGINS, MatchingRegion.REGULAR);
            context.ignore("UGEST/", MatchingType.BEGINS, MatchingRegion.REGULAR);// Doesn't look like a bot

            if (context.getUA().indexOf("(CK-")>-1)
                context.ignore("CK-[0-9a-zA-Z\\.\\-_]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);// Dunno what that is, but it looks widespread enough not to be a robot
            context.ignoreNextTokens(new Matcher[] {new Matcher("WinNT-PAI", MatchingType.EQUALS),
                                         new Matcher("[\\.0-9]+", MatchingType.REGEXP)
            },
            MatchingRegion.REGULAR); // Trojan http://www.threatexpert.com/report.aspx?md5=72e15bf94e8cb6ea2fc8d0626774ddd2

            context.ignoreNextTokens(new Matcher[] {new Matcher("sputnik", MatchingType.EQUALS),
                                         new Matcher("[\\.0-9]+", MatchingType.REGEXP)
            },
            MatchingRegion.REGULAR); // Sputnik.ru search engine plugin https://addons.mozilla.org/en-US/firefox/addon/sputnik-ru/

            while (context.ignoreNextTokens(new Matcher[] {new Matcher("GoogleToolbarFF", MatchingType.EQUALS),
                      new Matcher("[0-9]\\.[0-9]\\.[0-9]{8}", MatchingType.REGEXP)
            },
            MatchingRegion.REGULAR)!=null); // No big deal according to http://forums.mozfr.org/viewtopic.php?t=120841&p=771849


            if (result.getBrowser().getDescription().startsWith("Thunderbird")) {
                context.consume("Lightning/",  MatchingType.BEGINS, MatchingRegion.REGULAR); // Calendar extension to thunderbird
            }


        } else if (result.getBrowser().getDescription().startsWith("Lynx")) {
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
        context.ignore("Comcast Install 1.0", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("T-Mobile_Maple", MatchingType.EQUALS, MatchingRegion.REGULAR);
        while (context.ignore("Versatel.de ISDN 0404", MatchingType.EQUALS, MatchingRegion.PARENTHESIS));
        while (context.ignore("Cox High Speed Internet Customer", MatchingType.EQUALS, MatchingRegion.PARENTHESIS));
        while (context.ignore("Comcast", MatchingType.EQUALS, MatchingRegion.PARENTHESIS));
        if (result.getDevice().getDeviceType().isMobile()) {
            context.ignore("Orange", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // French operator
            context.ignore("SFR", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // French operator
            context.ignore("bouygues", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // French operator
            context.ignore("Vodafone", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Phone operator
            context.ignore("T-Mobile", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Phone operator
        }

        // Other
        context.consume("Silk-Accelerated=false",MatchingType.EQUALS, MatchingRegion.REGULAR);



        // Bullshitware
        while (context.ignore("FunWebProducts", MatchingType.REGEXP, MatchingRegion.BOTH)); // Is this malware? Probably.
        while (context.ignore("InfoPath\\.[0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS));
        context.ignore("Zune [0-9.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("OfficeLiveConnector\\.[0-9]\\.[0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("OfficeLivePatch\\.[0-9]\\.[0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("KKman[0-9]\\.[0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("FireDownload/[0-9]+(\\.[0-9]+)+", MatchingType.REGEXP, MatchingRegion.REGULAR);
        if (result.getBrowser().getFamily() == BrowserFamily.IE) {
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
        if (context.getUA().contains(";Alexa Toolbar"))
            context.ignore("Toolbar", MatchingType.EQUALS, MatchingRegion.REGULAR);
        context.ignore("AlexaToolbar/", MatchingType.BEGINS, MatchingRegion.REGULAR);
        context.ignore("ExaleadToolbar/", MatchingType.BEGINS, MatchingRegion.REGULAR);
        context.ignoreNextTokens(new Matcher[] {new Matcher("Alexa", MatchingType.EQUALS),
                                     new Matcher("Toolbar", MatchingType.EQUALS)
        },
        MatchingRegion.REGULAR);
        context.ignoreNextTokens(new Matcher[] {new Matcher("Congoo", MatchingType.EQUALS),
                                     new Matcher("NetPass", MatchingType.EQUALS)
        },
        MatchingRegion.REGULAR); // http://www.congoo.com/netpass/install.aspx

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
        context.ignore("FBSMTWB(002)?", MatchingType.REGEXP, MatchingRegion.BOTH); // Fast Browser Search toolbar
        context.ignore("BLNGBAR", MatchingType.EQUALS, MatchingRegion.BOTH); // Dunno

        context.ignoreNextTokens(new Matcher[] {new Matcher("MEGAUPLOAD", MatchingType.EQUALS),
                                     new Matcher("[123]\\.0(\\.)?", MatchingType.REGEXP)
        },
        MatchingRegion.REGULAR);

        context.ignore("AOLBuild [0-9]+\\.[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("SearchToolbar [0-9]\\.[0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("AskTbWBR/[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        while (context.ignore("MSN Optimized", MatchingType.EQUALS, MatchingRegion.PARENTHESIS));
        context.ignore("Dealio Toolbar [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignoreNextTokens(new Matcher[] {new Matcher("Dealio", MatchingType.EQUALS),
                                     new Matcher("Toolbar", MatchingType.EQUALS),
                                     new Matcher("[0-9\\.]+", MatchingType.REGEXP)
        },
        MatchingRegion.REGULAR);
        context.ignoreNextTokens(new Matcher[] {new Matcher("Scribd", MatchingType.EQUALS),
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
        consumeEntityFromIEAndFirefoxBuggy("eMusic", "DLM/[0-9\\.ab_]+", context, result); // why doe this adds itself to the UA, I wonder.


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
        context.consume("www.proxomitron.de", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);

        // Security / Viruses
        context.ignore("CyberSafe-IWA-Enable", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // TrustBroker CyberSafe
        context.ignore("AntivirXP08", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // Is this a virus? Cooool.
        if (result.getOperatingSystem().getFamily() == OSFamily.WINDOWS_NT) {
            context.ignore("AskTbARS/", MatchingType.BEGINS, MatchingRegion.BOTH); // Some remote working crap
        }
        while (context.ignore("Foxy/1", MatchingType.EQUALS, MatchingRegion.PARENTHESIS)); // *Maybe* some kind of proxy
        context.ignore("\\[eburo v[0-9].[0-9]\\]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("WinNT-EVI [0-9][0-9]\\.[0-9][0-9]\\.[1-2]0[0-9][0-9]", MatchingType.REGEXP, MatchingRegion.PARENTHESIS); // Antivir
        context.ignore("360SE", MatchingType.EQUALS, MatchingRegion.PARENTHESIS); // 360 Security Explorer https://kb.bluecoat.com/index?page=content&id=KB4979&actp=RSS
        context.ignore("Edutice/", MatchingType.BEGINS, MatchingRegion.REGULAR); // French device locking software for education
        while (context.ignore("hotvideobar_[0-9_]+", MatchingType.REGEXP, MatchingRegion.BOTH)); // Malware https://forums.malwarebytes.org/index.php?/topic/26285-hotvideobar/
        while (context.ignore("VB_gameztar", MatchingType.REGEXP, MatchingRegion.BOTH)); // Malware ? GamezTar is.
        consumeEntityFromIEAndFirefoxBuggy("WinTSI", "[0-9]{2}\\.[0-9]{2}\\.[0-9]{4}", context, result); // Personal Security Virus


        // DL manager
        context.ignore("QQDownload [0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);

        // Dev tools
        context.ignore("Google Page Speed Insights", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("Google Page Speed", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);


        // Unknown. These are unknown and don't look like bots, from their usage pattern.
        consumeEntityFromIEAndFirefox("VisualTB", null, context, result);

        while (consumeEntityFromIEAndFirefox("UGES[VULMYF]?", "[0-9\\.]+", context, result)); // Dunno
        consumeEntityFromIEAndFirefox("LUDI2", null, context, result); // Dunno
        while (consumeEntityFromIEAndFirefox("3P_U(RGD|SEC|VSM|VRM|AMG|ASE|PCPC|ASG)(ES|NL|FR|DE|IT)?", "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+", context, result)); // Dunno. Usage pattern doesn't point to a bot
        while (consumeEntityFromIEAndFirefox("3P_U(VRM)", "1\\.00\\.1", context, result)); // Dunno. Usage pattern doesn't point to a bot
        consumeEntityFromIEAndFirefox("CK=\\{[0-9a-zA-Z\\+/]+=?=?\\}", null, context, result); // Dunno. Usage pattern doesn't point to a bot

        context.ignore("YB/", MatchingType.BEGINS, MatchingRegion.BOTH);

        while (context.ignore("AtHome([A-Z][A-Z])?[0-9][0-9][0-9][0-9]?(SI)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS));
        while (context.ignore("QS [0-9\\.]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS));
        consumeEntityFromIEAndFirefox("BTRS[0-9]+", null, context, result);
        context.ignore("Google-TR", MatchingType.BEGINS, MatchingRegion.PARENTHESIS); // Looks like an addin, not a bot http://commerce.net/deciphering-fluffy-bunny/
        context.ignore("Zango [\\.0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("LBEXG/[\\.0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore(".NAP [\\.0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("ZangoToolbar [\\.0-9]+", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("BT-nasa", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("No IDN", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("APC", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("LEN2", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("Hemmit", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("N", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("QwestIE8(x64)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("CIBA", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("NET_mmhpset", MatchingType.EQUALS, MatchingRegion.BOTH);
        context.ignore("MDDS", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("MA[SE]M(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("MALN(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("MASB(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
        context.ignore("MAPB", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("SKY14", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("KPN", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("SHC", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("Alcohol Search", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        context.ignore("MSOCD", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
        if (result.getBrowser().getFamily() == BrowserFamily.FIREFOX) {
            context.ignore("YFF[0-9]+", MatchingType.REGEXP, MatchingRegion.REGULAR);
        }


        if (result.getBrowser().getFamily() == BrowserFamily.IE || result.getBrowser().getFamily() == BrowserFamily.OTHER_TRIDENT) {
            // TODO: http://www.whatismybrowser.com/developers/unknown-user-agent-fragments
            context.ignore("C[PM]DTDF", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);
            context.ignore("CPNTDF", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.ignore("HPMTDF", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.ignore("MDDS", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.ignore("MIDP", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.ignore("MAPT", MatchingType.EQUALS, MatchingRegion.PARENTHESIS);
            context.ignore("MASB(JS)?", MatchingType.REGEXP, MatchingRegion.PARENTHESIS);

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
        UserAgentDetectionResult res = null;
        if (ua == null || ua.length()<3) {
            res = new UserAgentDetectionResult();
            res.setDevice(new Device("",DeviceType.UNKNOWN,Brand.UNKNOWN,""));
            res.setBot(new Bot(Brand.UNKNOWN, BotFamily.NOT_A_BOT, "", "", ""));
            res.setLocale(new Locale());
            res.setOperatingSystem(new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"",""));
            res.setBrowser(new Browser(Brand.UNKNOWN,BrowserFamily.UNKNOWN,"",RenderingEngine.getUnknown()));
            return res;
        }
        UserAgentContext context = new UserAgentContext(ua);
        res = BotsHelper.getLibraries(context);
        if (res!=null) return res.wrapUp(context);

        res = new UserAgentDetectionResult();

        res.setBot(BotsHelper.getBot(context));

        res.setLocale(getLocale(context));

        res.setOperatingSystem(getOS(context));
        OS[]overrideOS = new OS[1];
        //res.operatingSystem = new OS(Brand.UNKNOWN,OSFamily.UNKNOWN,"browser", "browser");

        res.setBrowser(getBrowser(context, res.getOperatingSystem(), overrideOS));
        if (overrideOS[0] != null) {
            res.setOperatingSystem(overrideOS[0]);
        }

        res.setDevice(getDevice(context,res.getBrowser(),res.getOperatingSystem()));

        res.setLocale(getLocaleSecondPass(context, res));

        addExtensions(context, res);

        consumeRandomGarbage(context, res);

        BotsHelper.addLibrary(context, res);

        return res.wrapUp(context);
    }

    public static void test() {
        UserAgentContext.test();
    }
}