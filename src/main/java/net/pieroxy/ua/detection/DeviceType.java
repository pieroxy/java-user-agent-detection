package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
/**
* Describes the type of the device. You will mostly meet PHONEs, TABLETs and COMPUTERs out there on the web, along with BOTs.
*/
public enum DeviceType {
    /**
    * Smartphones or telephones (note that so-called Phablets are in this category).
    */
    PHONE(true),
    /**
    * Tablets such as iPads, Galaxy Tabs.
    */
    TABLET(true),
    /**
    * Desktop or laptop computer.
    */
    COMPUTER(false),
    /**
    * The user uses a simulator such as Google's Android SDK.
    */
    SDK(false),
    /**
    * The device type could not be determined.
    */
    UNKNOWN(false),
    /**
    * Game consoles such as Wii, PlayStation and XBox.
    */
    CONSOLE(false),
    /**
    * The device type could not be determined, but it is assumed to be mobile (either PHONE or TABLET.)
    */
    UNKNOWN_MOBILE(true);

    private boolean mobile;
    DeviceType(boolean l) {
        this.mobile = l;
    }
    /**
    * @return true if the device is a phone or a tablet.
    */
    public boolean isMobile() {
        return mobile;
    }
    @Override
    public String toString() {
        return name();
    }
    /**
    * @return the text representation of this DeviceType.
    */
    public String getLabel() {
        return name();
    }
}