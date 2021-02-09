package org.jenkinsci.plugins.googlelogin;

import hudson.security.GroupDetails;

import java.util.Set;

public class GoogleGroupDetails extends GroupDetails {

    private String name;
    private Set<String> members;

    public GoogleGroupDetails(String name, Set<String> members) {
        this.name = name;
        this.members = members;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Set<String> getMembers() {
        return members;
    }
}
