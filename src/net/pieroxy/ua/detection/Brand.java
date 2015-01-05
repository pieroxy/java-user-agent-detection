package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
/**
* The brand can apply to Browsers, Devices or OSes.
*/
public enum Brand {  HTC("HTC"),
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
                     MOTOROLA("Motorola"),
                     HUAWEI("Huawei"),
                     LENOVO("Lenovo"),
                     AMAZON("Amazon"),
                     TOSHIBA("Toshiba"),
                     OREGAN("Oregan Networks"),
                     ACER("Acer"),
                     GARMIN("Garmin"),
                     NOKIA("Nokia"),
                     KTTECH("KT Tech"),
                     LINUX("(Linux)"),
                     UNIXLIKE("(Unix-like)"),
                     YAHOO("Yahoo"),
                     OPENWAVE("Openwave"),
                     DELL("Dell"),
                     COMPAQ("Compaq"),
                     UNKNOWN(""),
                     OTHER("Other"),
                     UNKNOWN_ANDROID("(Android)"),
                     NINTENDO("Nintendo"),
                     MOZILLA("Mozilla"),
                     OPERA("Opera"),
                     CHROMIUM("The Chromium Project"),
                     KDE("KDE"),
                     ACCESSCO("Access Co. Ltd."),
                     NETSCAPE("Netscape"),
                     CUILL("Cuill"),
                     ORANGE("Orange"),
                     BE("Be Inc"),
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
                     BAIDU("Baidu");

                     private String label;
Brand(String l) {
    this.label = l;
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