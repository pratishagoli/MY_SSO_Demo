package com.example.ssoapp.controller;

import com.example.ssoapp.config.TenantContext; // 👈 NEW IMPORT
import com.example.ssoapp.dto.CreateTenantRequest;
import com.example.ssoapp.dto.TenantMinimalDTO;
import com.example.ssoapp.model.Tenant;
import com.example.ssoapp.model.User; // 👈 NEW IMPORT
import com.example.ssoapp.repository.UserRepository; // 👈 NEW IMPORT
import com.example.ssoapp.service.TenantService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;
import java.util.stream.Collectors; // 👈 NEW IMPORT

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

    @Autowired
    private UserRepository userRepository; // 👈 NEWLY INJECTED

    // ============================================================
    // ✅ 1. SUPERADMIN DASHBOARD
    // ============================================================
    @GetMapping("/dashboard")
    public String showDashboard(Model model, @AuthenticationPrincipal UserDetails userDetails) {
        List<TenantMinimalDTO> tenants = tenantService.findAllTenantMinimal();
        model.addAttribute("tenants", tenants);

        if (userDetails != null) {
            model.addAttribute("username", userDetails.getUsername());
        }

        if (!model.containsAttribute("createTenantRequest")) {
            model.addAttribute("createTenantRequest", new CreateTenantRequest());
        }
        return "superadmin-dashboard";
    }

    // ============================================================
    // ✅ 2. VIEW USERS FOR A SPECIFIC TENANT (THIS IS THE FIX)
    // ============================================================
    @GetMapping("/users")
    public String viewTenantUsers(@RequestParam("tenantId") Long tenantId, Model model) {

        // 1. Manually set the TenantContext for this request.
        // This forces userRepository.findAll() to only return users for this tenant.
        TenantContext.setTenantId(String.valueOf(tenantId));

        try {
            // 2. Fetch users for this tenant (Hibernate Filter is now active)
            List<User> allUsers = userRepository.findAll();

            // 3. Separate users into native and SSO lists (for the admindashboard.html template)
            List<User> nativeUsers = allUsers.stream()
                    .filter(u -> u.getProvider() == com.example.ssoapp.model.AuthProvider.LOCAL)
                    .collect(Collectors.toList());

            List<User> ssoUsers = allUsers.stream()
                    .filter(u -> u.getProvider() != com.example.ssoapp.model.AuthProvider.LOCAL)
                    .collect(Collectors.toList());

            // 4. Add data to the model
            model.addAttribute("nativeUsers", nativeUsers);
            model.addAttribute("ssoUsers", ssoUsers);
            model.addAttribute("tenantId", tenantId); // For context

            // 5. Return the correct template
            return "admindashboard"; // 👈 Renders templates/admindashboard.html

        } finally {
            // 6. CRITICAL: Always clear the context after use
            TenantContext.clear();
        }
    }


    // ============================================================
    // ✅ 3. LIST ALL TENANTS (Minimal DTO)
    // ============================================================
    @GetMapping("/tenants")
    public String listTenants(Model model) {
        // This is now redundant since the dashboard shows the list, so just redirect.
        return "redirect:/superadmin/dashboard";
    }

    // ============================================================
    // ✅ 4. SHOW CREATE TENANT FORM
    // ============================================================
    @GetMapping("/tenants/create")
    public String showCreateTenantForm(Model model) {
        // This is also handled by the dashboard page.
        return "redirect:/superadmin/dashboard";
    }

    // ============================================================
    // ✅ 5. CREATE TENANT (Form Submission)
    // ============================================================
    @PostMapping("/create-tenant")
    public String createTenant(@ModelAttribute CreateTenantRequest request,
                               Model model,
                               RedirectAttributes redirectAttributes) {
        try {
            tenantService.createTenant(
                    request.getOrgName(),
                    request.getAdminEmail(),
                    request.getAdminPassword(),
                    request.getSubdomain()
            );
            redirectAttributes.addFlashAttribute("successMessage", "Tenant created successfully!");
            return "redirect:/superadmin/dashboard";
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
            redirectAttributes.addFlashAttribute("createTenantRequest", request);
            return "redirect:/superadmin/dashboard";
        }
    }

    // ============================================================
    // ✅ 6. DELETE TENANT (Optional)
    // ============================================================
    @PostMapping("/tenants/{id}/delete")
    public String deleteTenant(@PathVariable Long id, RedirectAttributes redirectAttributes) {
        // Implement deletion if needed
        redirectAttributes.addFlashAttribute("successMessage", "Tenant deletion not yet implemented.");
        return "redirect:/superadmin/dashboard";
    }
}