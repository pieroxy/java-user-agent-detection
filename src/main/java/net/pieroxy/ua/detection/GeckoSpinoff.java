package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
class GeckoSpinoff {
    private String name;
    private String[]toRemove;
    private Brand brand;
    public GeckoSpinoff() {
        this(null, new String[0]);
    }
    public GeckoSpinoff(Brand b) {
        this(null, new String[0]);
        brand = b;
    }
    public GeckoSpinoff(String n) {
        this(n, new String[0]);
    }
    public GeckoSpinoff(String n, String[]tr) {
        name = n;
        toRemove = tr;
    }

    public String getName() {
        return name;
    }
    public String[]getToRemove() {
        return toRemove;
    }
    public Brand getBrand() {
        return brand;
    }
}