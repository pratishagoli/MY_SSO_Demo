package com.example.ssoapp.dto;

public class TenantMinimalDTO {
    private Long id;
    private String name;
    private String subdomain;

    public TenantMinimalDTO(Long id, String name, String subdomain) {
        this.id = id;
        this.name = name;
        this.subdomain = subdomain;
    }

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getSubdomain() {
        return subdomain;
    }
}