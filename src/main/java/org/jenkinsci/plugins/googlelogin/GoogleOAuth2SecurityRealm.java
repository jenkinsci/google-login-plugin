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

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.domains.URIRequirementBuilder;
import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.auth.openidconnect.IdTokenResponse;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.admin.directory.Directory;
import com.google.api.services.admin.directory.DirectoryScopes;
import com.google.api.services.admin.directory.model.Group;
import com.google.api.services.admin.directory.model.Groups;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.Sets;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.Failure;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.SecurityRealm;
import hudson.util.HttpResponses;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import org.acegisecurity.*;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import org.jenkinsci.plugins.plaincredentials.FileCredentials;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.DoNotUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.interceptor.RequirePOST;

import java.io.IOException;
import java.util.*;

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

    private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();

    private static final String SESSION_NAME = GoogleOAuth2SecurityRealm.class.getName() + ".OAuthSession";

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

    /**
     * If true, the redirection will happen based on the root URL determined from request.
     * If false, the redirection will happen based on the root URL configured in Jenkins.
     */
    private boolean rootURLFromRequest;

    /**
     * The Service Account Credentials for accessing the GSuite Admin SDK
     */
    private final String gsuiteServiceAccountCredentialsId;

    /**
     * GSuite user which executes the Google Group list api method of Admin SDK
     */
    private final String gsuiteImpersonationAccount;

    @DataBoundConstructor
    public GoogleOAuth2SecurityRealm(String clientId, String clientSecret, String domain, String gsuiteServiceAccountCredentialsId, String gsuiteImpersonationAccount) throws IOException {
        this.clientId = clientId;
        this.clientSecret = Secret.fromString(clientSecret);
        this.domain = Util.fixEmptyAndTrim(domain);
        this.gsuiteServiceAccountCredentialsId = gsuiteServiceAccountCredentialsId;
        this.gsuiteImpersonationAccount = gsuiteImpersonationAccount;
    }

    @SuppressWarnings("unused") // jelly
    public boolean isRootURLFromRequest() {
        return rootURLFromRequest;
    }

    @DataBoundSetter
    @SuppressWarnings("unused") // jelly
    public void setRootURLFromRequest(boolean rootURLFromRequest) {
        this.rootURLFromRequest = rootURLFromRequest;
    }

    @SuppressWarnings("unused") // jelly
    public String getClientId() {
        return clientId;
    }

    @SuppressWarnings("unused") // jelly
    public Secret getClientSecret() {
        return clientSecret;
    }

    public String getDomain() {
        return domain;
    }

    @SuppressWarnings("unused") // jelly
    public String getGsuiteServiceAccountCredentialsId() {
        return gsuiteServiceAccountCredentialsId;
    }

    @SuppressWarnings("unused") // jelly
    public String getGsuiteImpersonationAccount() {
        return gsuiteImpersonationAccount;
    }

    /**
     * Login begins with our {@link #doCommenceLogin(StaplerRequest, String,String)} method.
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
    @SuppressWarnings("unused") // stapler
    @Restricted(DoNotUse.class) // stapler only
    public HttpResponse doCommenceLogin(StaplerRequest request, @QueryParameter String from,  @Header("Referer") final String referer) throws IOException {
        final String redirectOnFinish;
        if (from != null && ! Util.isSafeToRedirectTo(from)) {
            redirectOnFinish = from;
        } else if (referer != null && ! Util.isSafeToRedirectTo(referer)) {
            redirectOnFinish = referer;
        } else {
            redirectOnFinish = getRootURL();
        }

        final AuthorizationCodeFlow flow = new AuthorizationCodeFlow.Builder(
                BearerToken.queryParameterAccessMethod(), HTTP_TRANSPORT, JSON_FACTORY, TOKEN_SERVER_URL,
                new ClientParametersAuthentication(clientId, clientSecret.getPlainText()), clientId, AUTHORIZATION_SERVER_URL)
                .setScopes(Arrays.asList(SCOPE))
                .build();

        OAuthSession oAuthSession = new OAuthSession(from, buildOAuthRedirectUrl(), domain) {
            @Override
            public HttpResponse onSuccess(String authorizationCode) {
                try {
                    IdTokenResponse response = IdTokenResponse.execute(
                            flow.newTokenRequest(authorizationCode).setRedirectUri(buildOAuthRedirectUrl()));
                    IdToken idToken = IdToken.parse(JSON_FACTORY, response.getIdToken());
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

                    Set<GrantedAuthority> authorities = new HashSet<>();
                    authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
                    authorities.addAll(getGroupsForUser(info.getEmail()));

                    // logs this user in.
                    UsernamePasswordAuthenticationToken token =
                            new UsernamePasswordAuthenticationToken(info.getEmail(), "", authorities.toArray(new GrantedAuthority[]{}));

                    // prevent session fixation attack
                    Stapler.getCurrentRequest().getSession().invalidate();
                    Stapler.getCurrentRequest().getSession();

                    SecurityContextHolder.getContext().setAuthentication(token);
                    // update the user profile.
                    User u = User.get(token.getName());
                    info.updateProfile(u);
                    // fire "LoggedIn" and not "authenticated" because
                    // "authenticated" is "Fired when a user was successfully authenticated by password."
                    // which is less relevant in our case
                    SecurityListener.fireLoggedIn(token.getName());
                    return new HttpRedirect(redirectOnFinish);

                } catch (IOException e) {
                    return HttpResponses.error(500, e);
                }

            }
        };
        request.getSession().setAttribute(SESSION_NAME, oAuthSession);
        return oAuthSession.doCommenceLogin(flow);
    }

    @VisibleForTesting
    boolean isDomainValid(Object tokenDomain) {
        if (domain == null) {
            return true;
        }
        StringTokenizer tokenizer = new StringTokenizer(domain, ",");
        while (tokenizer.hasMoreElements()) {
            String domainToTest = tokenizer.nextToken().trim();
            if (domainToTest.equals(tokenDomain)) {
                return true;
            }
        }
        return false;
    }

    private String buildOAuthRedirectUrl() {
        String rootUrl = getRootURL();
        if (rootUrl == null) {
            throw new NullPointerException("Jenkins root url should not be null");
        } else {
            return rootUrl + "securityRealm/finishLogin";
        }
    }

    private String getRootURL() {
        if (rootURLFromRequest) {
            return Jenkins.getInstance().getRootUrlFromRequest();
        } else {
            return Jenkins.getInstance().getRootUrl();
        }
    }

    private GoogleCredential getGoogleCredentials() throws IOException {
        if (this.gsuiteServiceAccountCredentialsId == null) {
            return null;
        }

        List<FileCredentials> serviceAccount = CredentialsMatchers.filter(
                CredentialsProvider.lookupCredentials(FileCredentials.class, Jenkins.getInstance(), ACL.SYSTEM, Collections.<DomainRequirement>emptyList()),
                CredentialsMatchers.withId(this.gsuiteServiceAccountCredentialsId)
        );

        if (serviceAccount.size() > 0) {
            GoogleCredential googleCredential = GoogleCredential.fromStream(serviceAccount.get(0).getContent());
            return new GoogleCredential.Builder()
                    .setTransport(HTTP_TRANSPORT)
                    .setJsonFactory(JSON_FACTORY)
                    .setServiceAccountUser(this.gsuiteImpersonationAccount)
                    .setServiceAccountId(googleCredential.getServiceAccountId())
                    .setServiceAccountScopes(Sets.newHashSet(DirectoryScopes.ADMIN_DIRECTORY_GROUP_READONLY))
                    .setServiceAccountPrivateKey(googleCredential.getServiceAccountPrivateKey())
                    .setServiceAccountPrivateKeyId(googleCredential.getServiceAccountPrivateKeyId())
                    .setTokenServerEncodedUrl(googleCredential.getTokenServerEncodedUrl())
                    .build();
        } else {
            return null;
        }
    }

    private Set<? extends GrantedAuthority> getGroupsForUser(String email) {
        if (this.gsuiteServiceAccountCredentialsId == null) {
            return Sets.newHashSet();
        }

        try {
            Directory googleAdminDirectoryService = new Directory.Builder(HTTP_TRANSPORT, JSON_FACTORY, getGoogleCredentials())
                    .setApplicationName(Jenkins.getInstance().getDisplayName()).build();
            Set<GrantedAuthorityImpl> groups = new HashSet<>();
            String pageToken = null;

            do {
                Groups groupsResult = googleAdminDirectoryService.groups().list()
                        .setUserKey(email)
                        .setMaxResults(200)
                        .execute();
                if (groupsResult == null || groupsResult.getGroups() == null) {
                    break;
                }
                for (Group group : groupsResult.getGroups()) {
                    groups.add(new GrantedAuthorityImpl(group.getEmail()));
                }
                pageToken = groupsResult.getNextPageToken();
            } while (pageToken != null);

            return groups;
        } catch (IOException e) {
            return Sets.newHashSet();
        }
    }


    /**
     * This is where the user comes back to at the end of the OpenID redirect ping-pong.
     */
    @SuppressWarnings("unused") // stapler
    @Restricted(DoNotUse.class) // stapler only
    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException {
        OAuthSession oAuthSession = (OAuthSession) request.getSession().getAttribute(SESSION_NAME);
        if (oAuthSession != null) {
            return oAuthSession.doFinishLogin(request);
        } else {
            return new Failure("Your Jenkins session has expired. Please login again.");
        }
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

        @RequirePOST
        public ListBoxModel doFillGsuiteServiceAccountCredentialsIdItems(@QueryParameter String serverUrl) {
            Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);
            return new StandardListBoxModel().withEmptySelection() //
                    .withMatching( //
                            CredentialsMatchers.instanceOf(FileCredentials.class),
                            CredentialsProvider.lookupCredentials(StandardCredentials.class, //
                                    Jenkins.getInstance(), //
                                    ACL.SYSTEM, //
                                    serverUrl != null ? URIRequirementBuilder.fromUri(serverUrl).build()
                                            : Collections.EMPTY_LIST //
                            ));

        }

    }
}
