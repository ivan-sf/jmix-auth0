package com.company.oidc1.user;

import io.jmix.oidc.user.DefaultJmixOidcUser;

public class MyUser extends DefaultJmixOidcUser {

    private String position;

    public String getPosition() {
        return position;
    }

    public void setPosition(String position) {
        this.position = position;
    }
}