package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
/**
* The brand can apply to Browsers, Devices or OSes.
*/
public enum Brand {  OBIGO("Obigo"),
                     INFRAWARE("Infraware Inc."),
                     HTC("HTC"),
                     APPLE("Apple"),
                     SAMSUNG("Samsung"),
                     SUN("SUN"),
                     SONY("Sony"),
                     RIM("RIM"),
                     NOVARRA("Novarra"),
                     MICROSOFT("Microsoft"),
                     WINDOWS("(Windows)"),
                     GOOGLE("Google"),
                     LG("LG"),
                     ZTE("Zte"),
                     ASUS("Asus"),
                     SHARP("Sharp"),
                     SANYO("Sanyo"),
                     WIKO("Wiko"),
                     DOMAINTOOLS("DomainTools", "http://www.domaintools.com"),
                     MOTOROLA("Motorola"),
                     HUAWEI("Huawei"),
                     LENOVO("Lenovo"),
                     AMAZON("Amazon"),
                     TOSHIBA("Toshiba"),
                     OREGAN("Oregan Networks"),
                     ACER("Acer"),
                     GARMIN("Garmin"),
                     NOKIA("Nokia"),
                     CUBOT("Cubot"),
                     KTTECH("KT Tech"),
                     LINUX("(Linux)"),
                     PANTECH("Pantech"),
                     UNIXLIKE("(Unix-like)"),
                     YAHOO("Yahoo"),
                     OPENWAVE("Openwave"),
                     PHOENIX("Phoenix Studio"),
                     DELL("Dell"),
                     COMPAQ("Compaq"),
                     UNKNOWN(""),
                     OTHER("Other"),
                     UNKNOWN_ANDROID("(Android)"),
                     AVANT("Avant Force"),
                     NINTENDO("Nintendo"),
                     MOZILLA("Mozilla"),
                     OPERA("Opera"),
                     NETEASE("NetEase","http://ir.netease.com/"),
                     ENTIREWEB("EntireWeb", "http://www.entireweb.com/"),
                     SEOPROFILER("SEO Profiler", "http://seoprofiler.com/"),
                     EXALEAD("Exalead", "https://www.exalead.com/"),
                     LUNASCAPE("Lunascape"),
                     CHROMIUM("The Chromium Project"),
                     OPENSOURCE("An Open Source Project"),
                     VIVALDI("Vivaldi Technologies"),
                     KDE("KDE"),
                     ACCESSCO("Access Co. Ltd."),
                     NETSCAPE("Netscape"),
                     CUILL("Cuill"),
                     ORANGE("Orange"),
                     SOGOU("Sogou"),
                     BE("Be Inc"),
                     HAIKU("Haiku Project"),
                     ASK("Ask"),
                     YACI("YaCy"),
                     YANDEX("Yandex"),
                     SGI("SGI"),
                     IBM("IBM"),
                     ELSOP("Elsop"),
                     ODYS("Odys"),
                     DELICIOUS("del.icio.us"),
                     DIGITAL_HP("HP (Digital)"),
                     HP("Hewlett-Packard"),
                     PALM("Palm"),
                     HANDSPRING("Handspring"),
                     ACORN("Acorn"),
                     BAIDU("Baidu"),
                     ARCHOS("Archos"),
                     UTSTARCOM("UTStarcom");

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
public String toString() {
    return getLabel();
}
                  }