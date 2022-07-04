package com.app.security;

public class EnumType {

    public enum ROLE {
        USER("USER"),
        ADMIN("ADMIN");
        private String value;

        ROLE(String value) {
            this.value = value;
        }

        public String getKey() {
            return name();
        }

        public String getValue() {
            return value;
        }
    }
}
