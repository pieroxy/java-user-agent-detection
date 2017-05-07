package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
/**
* Describes the device that produced the user-agent string.
*/
public class Device {

    private DeviceType deviceType;
    private Brand brand;
    private Brand manufacturer;
    private String architecture;
    private String device;
    private boolean touch;

    /** This constructor does not specify the <code>manufacturer</code> and assumes it is the same as the <code>brand</code>.
     * @param  _brand         The vendor of this device, and its manufacturer.
     * @param  _type          The type of this device (desktop, laptop, tablet, ...).
     * @param  _description   The text description of this device.
     * @param  _architecture  The cpu architecture of this device (x86, arm, ...).
     */
    public Device(String _architecture, DeviceType _type, Brand _brand, String _description) {
        this(_architecture,_type,_brand,_brand,_description);
    }

    /** This constructor allows for a manufacturer and a brand to be defined.
     * @param  _manufacturer  The manufacturer of this device.
     * @param  _brand         The vendor of this device.
     * @param  _type          The type of this device (desktop, laptop, tablet, ...).
     * @param  _description   The text description of this device.
     * @param  _architecture  The cpu architecture of this device (x86, arm, ...).
     */
    public Device(String _architecture, DeviceType _type, Brand _brand, Brand _manufacturer, String _description) {
        brand = _brand;
        manufacturer = _manufacturer;
        device = _description;
        deviceType = _type;
        architecture = _architecture;
    }

    /** This constructor allows for every field to be defined.
     * @param  _manufacturer  The manufacturer of this device.
     * @param  _brand         The vendor of this device.
     * @param  _type          The type of this device (desktop, laptop, tablet, ...).
     * @param  _description   The text description of this device.
     * @param  _architecture  The cpu architecture of this device (x86, arm, ...).
     * @param  _isTouch       Whether the device has touch capability or not.
     */
    public Device(String _architecture, DeviceType _type, Brand _brand, Brand _manufacturer, String _description, boolean _isTouch) {
        brand = _brand;
        manufacturer = _manufacturer;
        device = _description;
        deviceType = _type;
        architecture = _architecture;
        touch = _isTouch;
    }

    /** This constructor allows for touch to be defined.
     * @param  _brand         The vendor of this device.
     * @param  _type          The type of this device (desktop, laptop, tablet, ...).
     * @param  _description   The text description of this device.
     * @param  _architecture  The cpu architecture of this device (x86, arm, ...).
     * @param  _isTouch       Whether the device has touch capability or not.
     */
    public Device(String _architecture, DeviceType _type, Brand _brand, String _description, boolean _isTouch) {
        this(_architecture,_type,_brand,_brand,_description);
        touch = _isTouch;
    }

    /**
    * Sets the brand and the manufacturer of the device.
    * @param b the Brand to set in both fields.
    */
    public void setBrandAndManufacturer(Brand b) {
        brand=b;
        manufacturer=b;
    }
    public boolean equals(Object o) {
        if (o == null) return false;
        if (! (o instanceof Device)) return false;
        Device d = (Device) o;
        return
            ( (d.deviceType==null && deviceType==null) || d.deviceType.equals(deviceType) ) &&
            ( (d.brand==null && brand==null) || d.brand.equals(brand) ) &&
            ( (d.device==null && device==null) || d.device.equals(device) ) &&
            ( (d.architecture==null && architecture==null) || d.architecture.equals(architecture) ) &&
            ( (d.manufacturer==null && manufacturer==null) || d.manufacturer.equals(manufacturer) ) &&
            ( d.touch == touch );
    }
    public int hashCode() {
        int res = 0;
        if (deviceType!= null) {
            res *= 3;
            res += deviceType.hashCode();
        }
        if (device!= null) {
            res *= 3;
            res += device.hashCode();
        }
        if (architecture!= null) {
            res *= 3;
            res += architecture.hashCode();
        }
        if (manufacturer!= null) {
            res *= 3;
            res += manufacturer.hashCode();
        }
        if (brand!= null) {
            res *= 3;
            res += brand.hashCode();
        }
        if (touch) {
            res ++;
        }
        return res;
    }

    /** @return The type of the device. For example, COMPUTER, PHONE, TABLET, ... */
    public DeviceType getDeviceType() {
        return deviceType;
    }
    /** @param t The type of the device. For example, COMPUTER, PHONE, TABLET, ... */
    public void setDeviceType(DeviceType t) {
        deviceType = t;
    }
    /** @return The brand of the device. This is in general the manufacturer but can be different for example in the case of the Nexus line of Android devices.
     * For those, the brand will be GOOGLE. */
    public Brand getBrand() {
        return brand;
    }
    /** @return The manufacturer of the device. This is in general the brand but can be different for example in the case of the Nexus line of Android devices.
     * For those, the manufacturer will be either ASUS, SAMSUNG, LG, whoever built the device. */
    public Brand getManufacturer() {
        return manufacturer;
    }
    /** @return The architecture of the device. May be "i386", "arm", "x86_64", "Power PC" or any other architecture. */
    public String getArchitecture() {
        return architecture;
    }
    /** @param a The architecture of the device. May be "i386", "arm", "x86_64", "Power PC" or any other architecture. */
    public void setArchitecture(String a) {
        architecture = a;
    }
    /** @return The description of the device, for example "Galaxy S4" or "iPhone", ... */
    public String getDevice() {
        return device;
    }
    /** @param name The description of the device, for example "Galaxy S4" or "iPhone", ... */
    public void setDevice(String name) {
        device = name;
    }
    /** @return Whether the device has touch capabilities or not */
    public boolean isTouch() {
        return touch;
    }
    /** @param t Whether the device has touch capabilities or not */
    public void setTouch(boolean t) {
        touch=t;
    }

}