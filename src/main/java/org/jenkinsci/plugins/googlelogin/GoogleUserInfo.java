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

import com.google.api.client.util.Key;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import hudson.tasks.Mailer;
import hudson.util.Secret;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.StaplerRequest;

import java.io.IOException;

/**
 * Represents an identity information from the oauth provider.
 *
 * This is from https://www.googleapis.com/userinfo/v2/me
 */
public class GoogleUserInfo extends UserProperty {
    @Key
    public String family_name;

    @Key
    public String name;

    @Key
    public String picture;

    @Key
    public String locale;

    @Key
    public String gender;

    @Key
    public String email;

    @Key
    public String link;

    @Key
    public String given_name;

    @Key
    public String id;

    @Key
    public boolean verified_email;

    private boolean revokeAccessTokenOnLogout;

    public String getEmail() {
        return email;
    }

    public String getName() {
        return name;
    }

    public boolean isRevokeAccessTokenOnLogout() {
        return revokeAccessTokenOnLogout;
    }

    public void setRevokeAccessTokenOnLogout(boolean revokeAccessTokenOnLogout) {
        this.revokeAccessTokenOnLogout = revokeAccessTokenOnLogout;
    }

    /**
     * Updates the user information on Hudson based on the information in this identity.
     */
    public void updateProfile(User u) throws IOException {
        // update the user profile by the externally given information
        if (email != null)
            u.addProperty(new Mailer.UserProperty(email));

        if (name != null)
            u.setFullName(name);

        u.addProperty(this);
    }

    @Override
    public UserProperty reconfigure(StaplerRequest req, JSONObject form) throws Descriptor.FormException {
        this.revokeAccessTokenOnLogout = form.optBoolean("revokeAccessTokenOnLogout");
        return this;
    }

    @Extension
    public static class DescriptorImpl extends UserPropertyDescriptor {

        @Override
        public UserProperty newInstance(User user) {
            return null;
        }

        @Override
        public String getDisplayName() {
            return "Google Login";
        }
    }
}
