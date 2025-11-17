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

    // NOTE: Removed explicit constructor to rely on field injection for simplicity,
    // as @Autowired and @PersistenceContext are already present.

    // ============================================================
    // ✅ 1. SUPERADMIN DASHBOARD
    // ============================================================
    @GetMapping("/dashboard")
    public String showDashboard(Model model, @AuthenticationPrincipal UserDetails userDetails) {
        logger.info("✅ SuperAdmin dashboard accessed by: {}",
                userDetails != null ? userDetails.getUsername() : "unknown");

        // Log authorities for debugging
        if (userDetails != null) {
            logger.info("🔐 User authorities: {}", userDetails.getAuthorities());
        }

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

        // NOTE ON TENANT FILTER MANIPULATION:
        // This method manually enables the tenantFilter on the current Session
        // to bypass the multitenancy logic and explicitly query users for a single tenant,
        // which is a necessary SuperAdmin operation.

        Session session = null;
        try {
            // 1. Verify tenant exists
            Tenant tenant = tenantService.getTenantById(tenantId)
                    .orElseThrow(() -> new RuntimeException("Tenant not found with ID: " + tenantId));

            logger.info("Found tenant: {} (subdomain: {})", tenant.getName(), tenant.getSubdomain());

            // 2. Get Hibernate session and enable tenant filter
            session = entityManager.unwrap(Session.class);
            Filter filter = session.enableFilter("tenantFilter");
            // Need to set the tenantId as a String parameter as defined in the filter definition
            filter.setParameter("tenantId", String.valueOf(tenantId));

            logger.info("Hibernate tenant filter temporarily enabled for tenantId: {}", tenantId);

            // 3. Fetch users for this tenant (filter is now active)
            // userRepository.findAll() will now return only users matching the tenantId filter
            List<User> allUsers = userRepository.findAll();
            logger.info("Found {} users for tenant {}", allUsers.size(), tenantId);

            // 4. Separate users into native and SSO lists
            List<User> nativeUsers = allUsers.stream()
                    .filter(u -> u.getProvider() == com.example.ssoapp.model.AuthProvider.LOCAL)
                    .collect(Collectors.toList());

            List<User> ssoUsers = allUsers.stream()
                    .filter(u -> u.getProvider() != com.example.ssoapp.model.AuthProvider.LOCAL)
                    .collect(Collectors.toList());

            logger.info("Native users: {}, SSO users: {}", nativeUsers.size(), ssoUsers.size());

            // 5. Add data to the model
            model.addAttribute("nativeUsers", nativeUsers);
            model.addAttribute("ssoUsers", ssoUsers);
            model.addAttribute("tenantId", tenantId);
            model.addAttribute("tenantName", tenant.getName());

            return "admindashboard";

        } catch (Exception e) {
            logger.error("ERROR viewing tenant users for tenantId {}: {}", tenantId, e.getMessage(), e);
            // Add error to model for display
            model.addAttribute("error", "Failed to load users: " + e.getMessage());
            // Redirect back to dashboard with the error message
            return "redirect:/superadmin/dashboard";
        } finally {
            // CRITICAL: Ensure the filter is disabled when done, even if an exception occurred.
            if (session != null && session.getEnabledFilter("tenantFilter") != null) {
                session.disableFilter("tenantFilter");
                logger.info("Hibernate tenant filter disabled.");
            }
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
                    "Tenant created successfully! Subdomain: " + request.getSubdomain() + ".");
            return "redirect:/superadmin/dashboard";
        } catch (Exception e) {
            logger.error("Failed to create tenant: {}", e.getMessage(), e);
            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
            // Preserve the form data on redirect
            redirectAttributes.addFlashAttribute("createTenantRequest", request);
            return "redirect:/superadmin/dashboard";
        }
    }

    // ============================================================
    // ✅ 4. DELETE TENANT (Optional - Implement Later)
    // ============================================================
    @PostMapping("/tenants/{id}/delete")
    public String deleteTenant(@PathVariable Long id, RedirectAttributes redirectAttributes) {
        // You would typically call a tenantService.deleteTenant(id) here
        // For now, we'll just show the placeholder message
        redirectAttributes.addFlashAttribute("successMessage", "Tenant deletion not yet implemented for ID: " + id);
        return "redirect:/superadmin/dashboard";
    }
}