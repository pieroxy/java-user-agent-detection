package net.pieroxy.ua.tooling;

import net.pieroxy.ua.detection.UserAgentDetector;
import org.junit.Test;

/**
 * @author sam
 */
public class UserAgentDetectorTest {
    @Test
    public void testEnsureNullPointerExceptionBugFixed() {
        String userAgent = "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5 Build/MMB29Q; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/48.0.2564.106 Mobile Safari/537.36 MobileApp/1.0 (Android; 4.0.3; com.ebay.kr.g9)";
        UserAgentDetector detector = new UserAgentDetector();
        detector.parseUserAgent(userAgent);
    }
}
