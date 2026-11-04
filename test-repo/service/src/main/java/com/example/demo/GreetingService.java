package com.example.demo;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.yaml.snakeyaml.Yaml;

/** Uses log4j and snakeyaml so that bumping them is compile-checked. */
public final class GreetingService {
    private static final Logger LOG = LogManager.getLogger(GreetingService.class);

    public String greet(String yamlConfig) throws Exception {
        Object name = new Yaml().loadAs(yamlConfig, java.util.Map.class).get("name");
        LOG.info("greeting {}", name);
        return Greeting.toJson(String.valueOf(name));
    }
}
