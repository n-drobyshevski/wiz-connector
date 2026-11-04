package com.example.demo;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;
import org.apache.commons.text.WordUtils;

/** Tiny API class so that version bumps are compiled and tested. */
public final class Greeting {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Greeting() {
    }

    public static String toJson(String name) throws Exception {
        String clean = WordUtils.capitalizeFully(Strings.nullToEmpty(name).trim());
        return MAPPER.writeValueAsString(java.util.Map.of("greeting", "Hello, " + clean));
    }
}
