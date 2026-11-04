package com.example.demo;

import org.apache.commons.text.StringEscapeUtils;

/** Batch module with its own (already fixed) commons-text version. */
public final class Job {
    private Job() {
    }

    public static String escape(String input) {
        return StringEscapeUtils.escapeJson(input);
    }
}
