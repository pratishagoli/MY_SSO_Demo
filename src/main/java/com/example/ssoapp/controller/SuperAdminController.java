package com.example.ssoapp.controller;

import com.example.ssoapp.dto.CreateTenantRequest;
import com.example.ssoapp.service.TenantService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/superadmin")
@PreAuthorize("hasRole('SUPERADMIN')") // Secures all methods in this controller
public class SuperAdminController {

    @Autowired
    private TenantService tenantService;

    /**
     * Display the SuperAdmin dashboard, including the list of tenants.
     */
    @GetMapping("/dashboard")
    public String dashboard(Model model, @AuthenticationPrincipal UserDetails principal) {

        // Populate the model with SuperAdmin details and existing tenants
        model.addAttribute("username", principal.getUsername());
        model.addAttribute("tenants", tenantService.findAllTenantsMinimal());

        // The HTML template requires CSRF token for the form
        // Since we are redirecting from WebController, we need to ensure the token is available,
        // though Spring Security often handles this automatically for Thymeleaf forms.

        return "superadmin-dashboard"; // Renders src/main/resources/templates/superadmin-dashboard.html
    }

    /**
     * Handles the creation of a new tenant and its tenant admin user.
     */
    @PostMapping("/create-tenant")
    public String createTenant(@ModelAttribute CreateTenantRequest request, RedirectAttributes redirectAttributes) {
        try {
            // Validation (minimal for this simple case)
            if (request.getSubdomain() == null || request.getSubdomain().isEmpty()) {
                throw new IllegalArgumentException("Subdomain is required.");
            }

            tenantService.createTenant(request);

            redirectAttributes.addFlashAttribute("successMessage",
                    "Tenant '" + request.getSubdomain() + "' created successfully. Admin: " + request.getEmail());

            return "redirect:/superadmin/dashboard";

        } catch (IllegalArgumentException e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Error: " + e.getMessage());
            return "redirect:/superadmin/dashboard";
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Failed to create tenant due to server error.");
            return "redirect:/superadmin/dashboard";
        }
    }
}