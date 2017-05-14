package net.pieroxy.ua.detection;
import java.io.*;
import java.util.*;
public class VersionedObject {
    protected String version;
    protected String fullVersion;

    /**
     * This method sets both <code>version</code> and <code>fullVersion</code> attributes of this object.
     * It will set the <code>version</code> as the full version truncated to the first non numeric character, leaving the first '.' character in the mix.
     * @param  version   The full version number.
     * @param  nbChunks  The number of chunks that should be kept for the short version.
    */
    public void setFullVersionOneShot(String version, int nbChunks) {
        this.fullVersion = version;
        this.version = StringUtils.getShortVersion(version, nbChunks);
    }
    /** @return The two first numbers in the version of the rendering engine. Ex: 1.7 or 533.17 */
    public String getVersion() {
        return version;
    }
    /** @return The full version number of the rendering engine. Ex: 1.6.8 or 533.17.9 */
    public String getFullVersion() {
        return fullVersion;
    }

}