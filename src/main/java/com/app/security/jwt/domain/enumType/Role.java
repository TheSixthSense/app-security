package com.app.security.jwt.domain.enumType;

import com.app.security.util.EnumModel;

public enum Role implements EnumModel {
    USER("USER"),
    ADMIN("ADMIN");

    private String value;

    Role(String value) {
        this.value = value;
    }

    @Override
    public String getKey() {
        return name();
    }

    @Override
    public String getValue() {
        return value;
    }
}
