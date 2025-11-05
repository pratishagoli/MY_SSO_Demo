package com.example.ssoapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import java.util.TimeZone;

@SpringBootApplication
public class SsoappApplication {

	public static void main(String[] args) {

        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
		SpringApplication.run(SsoappApplication.class, args);
	}

}