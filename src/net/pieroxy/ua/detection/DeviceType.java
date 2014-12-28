package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
public enum DeviceType {  PHONE(true),
                          TABLET(true),
                          COMPUTER(false),
                          BOT(false),
                          SPAMBOT(false),
                          SDK(false),
                          UNKNOWN(false),
                          CONSOLE(false),
                          UNKNOWN_MOBILE(true);

                          private boolean mobile;
DeviceType(boolean l) {
    this.mobile = l;
}
public boolean isMobile() {
    return mobile;
}
public String toString() {
    return name();
}
public String getLabel() {
    return name();
}
                       }