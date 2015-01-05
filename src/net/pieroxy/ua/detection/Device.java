package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
/**
* Describes the device that produced the user-agent string.
*/
public class Device {
    public DeviceType deviceType;
    public Brand brand;
    public Brand manufacturer;
    public String architecture;
    public String device;
    public Device(String a, DeviceType dt, Brand b, String d) {
        this(a,dt,b,b,d);
    }
    public Device(String a, DeviceType dt, Brand b, Brand m, String d) {
        brand = b;
        manufacturer = m;
        device = d;
        deviceType = dt;
        architecture = a;
    }

    /**
    * Sets the brand and the manufacturer of the device.
    * @param b the Brand to set i both fields.
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
            ( (d.manufacturer==null && manufacturer==null) || d.manufacturer.equals(manufacturer) );
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
        return res;
    }
}