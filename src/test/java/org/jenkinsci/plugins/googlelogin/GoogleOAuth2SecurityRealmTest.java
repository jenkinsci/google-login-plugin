package org.jenkinsci.plugins.googlelogin;

import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class GoogleOAuth2SecurityRealmTest {

    @Rule
    public JenkinsRule r = new JenkinsRule();

    @Test
    public void accidentallyBlank() throws IOException {
        GoogleOAuth2SecurityRealm instance = setupInstanceWithDomains(" ");
        assertTrue(instance.isDomainValid("acme.com"));
        assertTrue(instance.isDomainValid("mycompany.com"));
    }

    @Test
    public void trailingSpace() throws IOException {
        GoogleOAuth2SecurityRealm instance = setupInstanceWithDomains("acme.com ");
        assertTrue(instance.isDomainValid("acme.com"));
        assertFalse(instance.isDomainValid("mycompany.com"));
    }

    @Test
    public void validSingleDomain() throws IOException {
        GoogleOAuth2SecurityRealm instance = setupInstanceWithDomains("acme.com");
        assertTrue(instance.isDomainValid("acme.com"));
        assertFalse(instance.isDomainValid("mycompany.com"));
    }

    @Test
    public void validTwoDomains() throws IOException {
        GoogleOAuth2SecurityRealm instance = setupInstanceWithDomains("acme.com,mycompany.com");
        assertTrue(instance.isDomainValid("acme.com"));
        assertTrue(instance.isDomainValid("mycompany.com"));
    }

    @Test
    public void validTwoDomainsWithLeadingSpaces() throws IOException {
        GoogleOAuth2SecurityRealm instance = setupInstanceWithDomains("acme.com, mycompany.com");
        assertTrue(instance.isDomainValid("acme.com"));
        assertTrue(instance.isDomainValid("mycompany.com"));
    }

    private GoogleOAuth2SecurityRealm setupInstanceWithDomains(String domains) throws IOException {
        String clientId = "clientId";
        String clientSecret = "clientSecret";
        return new GoogleOAuth2SecurityRealm(clientId, clientSecret, domains, null, null);
    }

    @Test
    public void testRedirect() throws Exception {
        GoogleOAuth2SecurityRealm instance = setupInstanceWithDomains("acme.com");
        assertEquals("relative", instance.getRedirectOnFinish("relative", null));
        assertEquals("relative", instance.getRedirectOnFinish("relative", "referrer"));
        assertEquals("relative", instance.getRedirectOnFinish("relative", "http://absolute"));
        assertEquals("relative", instance.getRedirectOnFinish("http://absolute", "relative"));
        assertEquals("relative", instance.getRedirectOnFinish("//protocol-relative", "relative"));
        assertEquals("relative", instance.getRedirectOnFinish(null, "relative"));
        String rootURL = r.getURL().toExternalForm();
        assertEquals(rootURL, instance.getRedirectOnFinish("http://absolute", null));
        assertEquals(rootURL, instance.getRedirectOnFinish("http://absolute", "http://absolute2"));
    }
}
