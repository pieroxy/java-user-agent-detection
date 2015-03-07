package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
/**
* The brand can apply to Browsers, Devices or OSes.
*/
public enum Brand {  OBIGO("Obigo","http://www.obigo.com"),
                     INFRAWARE("Infraware Inc."),
                     HTC("HTC", "http://www.htc.com"),
                     APPLE("Apple", "http://www.apple.com"),
                     SAMSUNG("Samsung", "http://www.samsung.com"),
                     SUN("SUN", "http://en.wikipedia.org/wiki/Sun_Microsystems"),
                     SONY("Sony", "http://www.sony.com"),
                     RIM("BlackBerry", "http://www.blackberry.com"),
                     NOVARRA("Novarra", "http://company.nokia.com/en/news/press-releases/2010/03/26/nokia-acquires-novarra"),
                     MICROSOFT("Microsoft", "http://www.microsoft.com"),
                     WINDOWS("(Windows)"),
                     GOOGLE("Google","http://www.google.com"),
                     LG("LG","http://www.lg.com"),
                     ZTE("Zte","http://wwwen.zte.com.cn"),
                     ASUS("Asus","http://www.asus.com"),
                     SHARP("Sharp","http://sharp-world.com"),
                     SANYO("Sanyo","http://panasonic.net/sanyo"),
                     WIKO("Wiko", "http://world.wikomobile.com"),
                     DOMAINTOOLS("DomainTools", "http://www.domaintools.com"),
                     MOTOROLA("Motorola", "http://www.motorola.com"),
                     HUAWEI("Huawei", "http://www.huawei.com"),
                     LENOVO("Lenovo", "http://www.lenovo.com"),
                     AMAZON("Amazon", "http://www.amazon.com"),
                     TOSHIBA("Toshiba", "http://www.toshiba.com"),
                     OREGAN("Oregan Networks", "http://oregan.net"),
                     ACER("Acer", "http://www.acer.com"),
                     GARMIN("Garmin", "http://www.garmin.com"),
                     NOKIA("Nokia", "http://www.nokia.com"),
                     CUBOT("Cubot", "http://www.cubot.net"),
                     KTTECH("KT Tech", "http://www.kttech.co.kr"),
                     LINUX("(Linux)"),
                     PANTECH("Pantech", "http://www.pantech.com"),
                     UNIXLIKE("(Unix-like)"),
                     YAHOO("Yahoo", "http://www.yahoo.com"),
                     OPENWAVE("Openwave", "http://www.openwave.com"),
                     PHOENIX("Phoenix Studio", "http://www.theworld.cn"),
                     DELL("Dell", "http://www.dell.com"),
                     COMPAQ("Compaq", "http://www.compaq.com"),
                     UNKNOWN(""),
                     OTHER("Other"),
                     UNKNOWN_ANDROID("(Android)"),
                     AVANT("Avant Force", "http://www.avantbrowser.com"),
                     NINTENDO("Nintendo", "http://www.nintendo.com"),
                     MOZILLA("Mozilla", "http://www.mozilla.org"),
                     OPERA("Opera", "http://www.opera.com"),
                     NETEASE("NetEase","http://ir.netease.com"),
                     ENTIREWEB("EntireWeb", "http://www.entireweb.com"),
                     SEOPROFILER("SEO Profiler", "http://seoprofiler.com"),
                     EXALEAD("Exalead", "https://www.exalead.com"),
                     LUNASCAPE("Lunascape", "http://www.lunascape.tv"),
                     CHROMIUM("The Chromium Project", "http://www.chromium.org"),
                     OPENSOURCE("An Open Source Project"),
                     VIVALDI("Vivaldi Technologies", "https://vivaldi.com"),
                     KDE("KDE", "http://www.kde.org"),
                     ACCESSCO("Access Co. Ltd.", "http://www.access-company.com"),
                     NETSCAPE("Netscape", "http://en.wikipedia.org/wiki/Netscape"),
                     CUIL("Cuil", "http://en.wikipedia.org/wiki/Cuil"),
                     ORANGE("Orange", "http://www.orange.com"),
                     SOGOU("Sogou", "http://www.sogou.com"),
                     BE("Be Inc", "http://en.wikipedia.org/wiki/Be_Inc."),
                     HAIKU("Haiku Project", "http://haiku-os.org"),
                     ASK("Ask", "http://ask.com"),
                     YACI("YaCy", "http://yacy.net"),
                     YANDEX("Yandex", "http://www.yandex.ru"),
                     SGI("SGI", "http://en.wikipedia.org/wiki/Silicon_Graphics"),
                     IBM("IBM", "http://www.ibm.com"),
                     ELSOP("Elsop", "http://www.elsop.com"),
                     ODYS("Odys", "http://www.odys.de"),
                     DELICIOUS("del.icio.us", "http://delicious.com"),
                     DIGITAL_HP("HP (Digital)", "http://www.hp.com"),
                     HP("Hewlett-Packard", "http://www.hp.com"),
                     PALM("Palm", "http://en.wikipedia.org/wiki/Palm_%28PDA%29"),
                     HANDSPRING("Handspring", "http://en.wikipedia.org/wiki/Handspring_%28company%29"),
                     ACORN("Acorn", "http://en.wikipedia.org/wiki/Acorn_Computers"),
                     BAIDU("Baidu", "http://www.baidu.com"),
                     ARCHOS("Archos", "http://www.archos.com"),
                     UTSTARCOM("UTStarcom", "http://www.utstar.com");

                     private String label;
                     private String website;

Brand(String l) {
    this.label = l;
}

Brand(String l, String url) {
    this.label = l;
    this.website = url;
}
/**
* @return the string representation of the brand.
*/
public String getLabel() {
    return label;
}
/**
* @return the url of the official website of this brand. If the website is not available anymore, the english wikipedia page of the brand is returned, ot the url for the company having bought it, or the official notice of acquisition.
*/
public String getWebsite() {
    return website;
}
public String toString() {
    return getLabel();
}
                  }