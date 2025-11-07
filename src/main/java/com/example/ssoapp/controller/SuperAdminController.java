package com.example.ssoapp.controller;

import com.example.ssoapp.dto.CreateTenantRequest;
import com.example.ssoapp.dto.TenantMinimalDTO;
import com.example.ssoapp.model.Tenant;
import com.example.ssoapp.service.TenantService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Controller for SuperAdmin operations:
 * - View all tenants
 * - Create new tenant
 * - Delete or manage tenants
 */
@Controller
@RequestMapping("/superadmin")
public class SuperAdminController {

    @Autowired
    private TenantService tenantService;

    // ============================================================
    // ✅ LIST ALL TENANTS (Minimal DTO)
    // ============================================================
    @GetMapping("/tenants")
    public String listTenants(Model model) {
        List<TenantMinimalDTO> tenants = tenantService.findAllTenantMinimal(); // ✅ non-static call
        model.addAttribute("tenants", tenants);
        return "superadmin/tenant-list";
    }

    // ============================================================
    // ✅ SHOW CREATE TENANT FORM
    // ============================================================
    @GetMapping("/tenants/create")
    public String showCreateTenantForm(Model model) {
        model.addAttribute("createTenantRequest", new CreateTenantRequest());
        return "superadmin/create-tenant";
    }

    // ============================================================
    // ✅ CREATE TENANT (Form Submission)
    // ============================================================
    @PostMapping("/tenants")
    public String createTenant(@ModelAttribute CreateTenantRequest request, Model model) {
        try {
            tenantService.createTenant(
                    request.getOrgName(),
                    request.getAdminEmail(),
                    request.getAdminPassword(),
                    request.getSubdomain()
            );
            return "redirect:/superadmin/tenants?success=true";
        } catch (Exception e) {
            model.addAttribute("error", e.getMessage());
            return "superadmin/create-tenant";
        }
    }

    // ============================================================
    // ✅ DELETE TENANT (Optional)
    // ============================================================
    @PostMapping("/tenants/{id}/delete")
    public String deleteTenant(@PathVariable Long id) {
        // Implement deletion if needed
        return "redirect:/superadmin/tenants";
    }
}

