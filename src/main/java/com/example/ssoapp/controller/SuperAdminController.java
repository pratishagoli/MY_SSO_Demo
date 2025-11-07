package com.example.ssoapp.controller;

import com.example.ssoapp.config.TenantContext;
import com.example.ssoapp.dto.CreateTenantRequest;
import com.example.ssoapp.dto.TenantMinimalDTO;
import com.example.ssoapp.model.Tenant;
import com.example.ssoapp.model.User;
import com.example.ssoapp.repository.UserRepository;
import com.example.ssoapp.service.TenantService;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.hibernate.Filter;
import org.hibernate.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Controller for SuperAdmin operations:
 * - View all tenants
 * - Create new tenant
 * - View users for a specific tenant
 */
@Controller
@RequestMapping("/superadmin")
public class SuperAdminController {

    private static final Logger logger = LoggerFactory.getLogger(SuperAdminController.class);

    @Autowired
    private TenantService tenantService;

    @Autowired
    private UserRepository userRepository;

    @PersistenceContext
    private EntityManager entityManager;

    // ============================================================
    // ✅ 1. SUPERADMIN DASHBOARD
    // ============================================================
    @GetMapping("/dashboard")
    public String showDashboard(Model model, @AuthenticationPrincipal UserDetails userDetails) {
        logger.info("SuperAdmin dashboard accessed by: {}", userDetails != null ? userDetails.getUsername() : "unknown");

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
    // ✅ 2. VIEW USERS FOR A SPECIFIC TENANT (FIXED VERSION)
    // ============================================================
    @GetMapping("/users")
    public String viewTenantUsers(@RequestParam("tenantId") Long tenantId, Model model) {
        logger.info("=== SuperAdmin viewing users for tenantId: {} ===", tenantId);

        try {
            // Verify tenant exists
            Tenant tenant = tenantService.getTenantById(tenantId)
                    .orElseThrow(() -> new RuntimeException("Tenant not found with ID: " + tenantId));

            logger.info("Found tenant: {} (subdomain: {})", tenant.getName(), tenant.getSubdomain());

            // Get Hibernate session and enable tenant filter
            Session session = entityManager.unwrap(Session.class);
            Filter filter = session.enableFilter("tenantFilter");
            filter.setParameter("tenantId", tenantId);

            logger.info("Hibernate tenant filter enabled for tenantId: {}", tenantId);

            // Fetch users for this tenant (filter is now active)
            List<User> allUsers = userRepository.findAll();
            logger.info("Found {} users for tenant {}", allUsers.size(), tenantId);

            // Separate users into native and SSO lists
            List<User> nativeUsers = allUsers.stream()
                    .filter(u -> u.getProvider() == com.example.ssoapp.model.AuthProvider.LOCAL)
                    .collect(Collectors.toList());

            List<User> ssoUsers = allUsers.stream()
                    .filter(u -> u.getProvider() != com.example.ssoapp.model.AuthProvider.LOCAL)
                    .collect(Collectors.toList());

            logger.info("Native users: {}, SSO users: {}", nativeUsers.size(), ssoUsers.size());

            // Add data to the model
            model.addAttribute("nativeUsers", nativeUsers);
            model.addAttribute("ssoUsers", ssoUsers);
            model.addAttribute("tenantId", tenantId);
            model.addAttribute("tenantName", tenant.getName());

            // Disable the filter after use
            session.disableFilter("tenantFilter");

            return "admindashboard";

        } catch (Exception e) {
            logger.error("ERROR viewing tenant users for tenantId {}: {}", tenantId, e.getMessage(), e);
            model.addAttribute("errorMessage", "Failed to load users: " + e.getMessage());
            return "redirect:/superadmin/dashboard?error=load_users_failed";
        }
    }

    // ============================================================
    // ✅ 3. CREATE TENANT (Form Submission)
    // ============================================================
    @PostMapping("/create-tenant")
    public String createTenant(@ModelAttribute CreateTenantRequest request,
                               Model model,
                               RedirectAttributes redirectAttributes) {
        logger.info("Creating tenant with subdomain: {}", request.getSubdomain());

        try {
            tenantService.createTenant(
                    request.getOrgName(),
                    request.getAdminEmail(),
                    request.getAdminPassword(),
                    request.getSubdomain()
            );
            redirectAttributes.addFlashAttribute("successMessage",
                    "Tenant created successfully! Subdomain: " + request.getSubdomain() + ".localhost");
            return "redirect:/superadmin/dashboard";
        } catch (Exception e) {
            logger.error("Failed to create tenant: {}", e.getMessage(), e);
            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
            redirectAttributes.addFlashAttribute("createTenantRequest", request);
            return "redirect:/superadmin/dashboard";
        }
    }

    // ============================================================
    // ✅ 4. DELETE TENANT (Optional - Implement Later)
    // ============================================================
    @PostMapping("/tenants/{id}/delete")
    public String deleteTenant(@PathVariable Long id, RedirectAttributes redirectAttributes) {
        redirectAttributes.addFlashAttribute("successMessage", "Tenant deletion not yet implemented.");
        return "redirect:/superadmin/dashboard";
    }
}