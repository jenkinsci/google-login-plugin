package org.jenkinsci.plugins.googlelogin;

import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import org.apache.commons.lang.StringUtils;
import java.io.IOException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class GoogleOAuth2SecurityRealmTest {

    @Rule
    public JenkinsRule jenkins = new JenkinsRule();

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
}
