package com.example.demo;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class GreetingTest {
    @Test
    void rendersJson() throws Exception {
        assertEquals("{\"greeting\":\"Hello, Ada Lovelace\"}", Greeting.toJson("  ada lovelace "));
    }
}
