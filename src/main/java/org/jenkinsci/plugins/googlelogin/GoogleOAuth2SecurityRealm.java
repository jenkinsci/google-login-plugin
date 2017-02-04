/*
 * The MIT License
 *
 * Copyright (c) 2004-2009, Sun Microsystems, Inc., Kohsuke Kawaguchi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.googlelogin;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.auth.openidconnect.IdTokenResponse;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.common.annotations.VisibleForTesting;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.SecurityRealm;
import hudson.util.HttpResponses;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

import org.apache.commons.lang.StringUtils;
import javax.servlet.ServletException;
import java.io.IOException;
import java.util.Arrays;
import java.util.StringTokenizer;

/**
 * Login with Google using OpenID Connect / OAuth 2
 *
 */
public class GoogleOAuth2SecurityRealm extends SecurityRealm {

    /**
     * OAuth 2 scope. This is enough to call a variety of userinfo api's.
     */
    private static final String SCOPE = "profile email";

    /**
     * Global instance of the JSON factory.
     */
    private static final JsonFactory JSON_FACTORY = new JacksonFactory();

    private static final GenericUrl TOKEN_SERVER_URL = new GenericUrl("https://accounts.google.com/o/oauth2/token");
    private static final String AUTHORIZATION_SERVER_URL = "https://accounts.google.com/o/oauth2/auth";
    private static final String REVOKE_URL = "https://accounts.google.com/o/oauth2/revoke?token=%s";

    private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();

    /**
     * The clientID from the Google Developer console.
     */
    private final String clientId;
    /**
     * The client secret from the Google Developer console.
     */
    private final Secret clientSecret;

    /**
     * If this is non-null, access will be restricted to this domain.
     */
    private final String domain;

    private boolean revokeAccessTokenOnLogout;

    @DataBoundConstructor
    public GoogleOAuth2SecurityRealm(String clientId, String clientSecret, String domain) throws IOException {
        this.clientId = clientId;
        this.clientSecret = Secret.fromString(clientSecret);
        this.domain = Util.fixEmptyAndTrim(domain);
    }

    @DataBoundSetter
    public void setRevokeAccessTokenOnLogout(boolean revokeAccessTokenOnLogout) {
        this.revokeAccessTokenOnLogout = revokeAccessTokenOnLogout;
    }

    public boolean isRevokeAccessTokenOnLogout() {
        return revokeAccessTokenOnLogout;
    }

    public String getClientId() {
        return clientId;
    }

    public Secret getClientSecret() {
        return clientSecret;
    }

    public String getDomain() {
        return domain;
    }

    /**
     * Login begins with our {@link #doCommenceLogin(String,String)} method.
     */
    @Override
    public String getLoginUrl() {
        return "securityRealm/commenceLogin";
    }

    /**
     * Acegi has this notion that first an {@link org.acegisecurity.Authentication} object is created
     * by collecting user information and then the act of authentication is done
     * later (by {@link org.acegisecurity.AuthenticationManager}) to verify it. But in case of OpenID,
     * we create an {@link org.acegisecurity.Authentication} only after we verified the user identity,
     * so {@link org.acegisecurity.AuthenticationManager} becomes no-op.
     */
    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(
                new AuthenticationManager() {
                    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                        if (authentication instanceof AnonymousAuthenticationToken)
                            return authentication;
                        throw new BadCredentialsException("Unexpected authentication type: " + authentication);
                    }
                }
        );
    }

    @Override
    protected String getPostLogOutUrl(StaplerRequest req, Authentication auth) {
        return "securityRealm/loggedOut";
    }

    /**
     * The login process starts from here.
     */
    public HttpResponse doCommenceLogin(@QueryParameter String from,  @Header("Referer") final String referer) throws IOException {
        final String redirectOnFinish;
        if (from != null) {
            redirectOnFinish = from;
        } else if (referer != null) {
            redirectOnFinish = referer;
        } else {
            redirectOnFinish = Jenkins.getInstance().getRootUrl();
        }

        final AuthorizationCodeFlow flow = new AuthorizationCodeFlow.Builder(
                BearerToken.queryParameterAccessMethod(), HTTP_TRANSPORT, JSON_FACTORY, TOKEN_SERVER_URL,
                new ClientParametersAuthentication(clientId, clientSecret.getPlainText()), clientId, AUTHORIZATION_SERVER_URL)
                .setScopes(Arrays.asList(SCOPE))
                .build();

        return new OAuthSession(flow,from, buildOAuthRedirectUrl(), domain) {
            @Override
            public HttpResponse onSuccess(String authorizationCode) {
                try {
                    IdTokenResponse response = IdTokenResponse.execute(
                            flow.newTokenRequest(authorizationCode).setRedirectUri(buildOAuthRedirectUrl()));
                    IdToken idToken = IdToken.parse(JSON_FACTORY,response.getIdToken());
                    Object hd = idToken.getPayload().get("hd");
                    if (!isDomainValid(hd)) {
                        return HttpResponses.errorWithoutStack(401, "Unauthorized");
                    }
                    final Credential credential = flow.createAndStoreCredential(response, null);

                    HttpRequestFactory requestFactory =
                            HTTP_TRANSPORT.createRequestFactory(new HttpRequestInitializer() {
                                public void initialize(HttpRequest request) throws IOException {
                                    credential.initialize(request);
                                    request.setParser(new JsonObjectParser(JSON_FACTORY));
                                }
                            });
                    GenericUrl url = new GenericUrl("https://www.googleapis.com/userinfo/v2/me");

                    HttpRequest request = requestFactory.buildGetRequest(url);

                    GoogleUserInfo info = request.execute().parseAs(GoogleUserInfo.class);
                    GrantedAuthority[] authorities = new GrantedAuthority[]{SecurityRealm.AUTHENTICATED_AUTHORITY};
                    // logs this user in.
                    UsernamePasswordAuthenticationToken token =
                            new UsernamePasswordAuthenticationToken(info.getEmail(), credential.getAccessToken(), authorities);
                    SecurityContextHolder.getContext().setAuthentication(token);
                    // update the user profile.
                    User u = User.get(token.getName());
                    info.updateProfile(u);
                    return new HttpRedirect(redirectOnFinish);

                } catch (IOException e) {
                    return HttpResponses.error(500,e);
                }

            }
        }.doCommenceLogin();
    }

    @VisibleForTesting
    boolean isDomainValid(Object tokenDomain) {
        if (domain == null) {
            return true;
        }
        StringTokenizer tokenizer = new StringTokenizer(domain, ",");
        while (tokenizer.hasMoreElements()) {
            if (tokenizer.nextToken().equals(tokenDomain)) {
                return true;
            }
        }
        return false;
    }

    private String buildOAuthRedirectUrl() {
        String rootUrl = Jenkins.getInstance().getRootUrl();
        if (rootUrl == null) {
            throw new NullPointerException("Jenkins root url should not be null");
        } else {
            return rootUrl + "securityRealm/finishLogin";
        }
    }


    /**
     * This is where the user comes back to at the end of the OpenID redirect ping-pong.
     */
    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException {
        return OAuthSession.getCurrent().doFinishLogin(request);
    }

    @Override
    public void doLogout(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException {
        User currentUser = User.current();
        if (currentUser != null) {
            GoogleUserInfo userInfo = currentUser.getProperty(GoogleUserInfo.class);
            if (userInfo != null && (revokeAccessTokenOnLogout || userInfo.isRevokeAccessTokenOnLogout())) {
                HttpRequestFactory requestFactory = HTTP_TRANSPORT.createRequestFactory();
                Object credentials = SecurityContextHolder.getContext().getAuthentication().getCredentials();
                if (credentials instanceof String) {
                    String accessToken = (String) credentials;
                    if (StringUtils.isNotBlank(accessToken)) {
                        GenericUrl url = new GenericUrl(String.format(REVOKE_URL, accessToken));
                        HttpRequest request = requestFactory.buildGetRequest(url);
                        request.execute();
                    }
                }
            }
        }
        super.doLogout(req, rsp);
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        public String getDisplayName() {
            return "Login with Google";
        }
        /*
         TODO: Find some way to validate the credentials.
         This current returns "Invalid OAuth 2 grant type: CLIENT_CREDENTIALS"
        public FormValidation doCheckApiSecret(@QueryParameter String clientId, @QueryParameter String value) {
            if (clientId == null) {
                return FormValidation.error("API Key is required");
            }
            ClientCredentialsTokenRequest tokenRequest = new ClientCredentialsTokenRequest(HTTP_TRANSPORT, JSON_FACTORY, TOKEN_SERVER_URL)
                    .setClientAuthentication(new ClientParametersAuthentication(clientId, value))
                    .setScopes(Collections.singleton(SCOPE));
            try {
                TokenResponse response = tokenRequest.execute();
                return FormValidation.ok("Credentials are valid");
            } catch (IOException e) {
                return FormValidation.error(e,"Credentials are invalid, or do not have expected scopes.");
            }
        }
            */

    }
}
