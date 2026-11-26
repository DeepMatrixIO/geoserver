/* (c) 2018 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.keycloak;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.geotools.util.logging.Logging;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.spi.AuthChallenge;
import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.keycloak.adapters.springsecurity.facade.SimpleHttpFacade;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * Wraps the result of an attempt to authenticate. This is either valid auth, or a challenge in
 * order to obtain them.
 */
class AuthResults implements AuthenticationEntryPoint {

    private static final Logger LOG = Logging.getLogger(AuthResults.class);

    /** Request attribute: why the request did not authenticate (set by the filter). */
    static final String FAILURE_REASON = AuthResults.class.getName() + ".reason";

    private final Authentication authentication;
    private final AuthChallenge challenge;

    /** Create a FORBIDDEN result. */
    public AuthResults() {
        this.authentication = null;
        this.challenge = null;
    }

    /**
     * Create a failed result with a potential challenge to obtain credentials and retry.
     *
     * @param challenge instructions to obtain credentials
     */
    public AuthResults(AuthChallenge challenge) {
        this.authentication = null;
        this.challenge = challenge;
    }

    /**
     * Create a successful result.
     *
     * @param authentication valid credentials
     */
    public AuthResults(Authentication authentication) {
        Object username = null;
        Object details = null;
        if (authentication.getDetails() instanceof SimpleKeycloakAccount) {
            details = (SimpleKeycloakAccount) authentication.getDetails();

            assert ((SimpleKeycloakAccount) details).getPrincipal() instanceof KeycloakPrincipal;
            final KeycloakPrincipal principal =
                    (KeycloakPrincipal) ((SimpleKeycloakAccount) details).getPrincipal();

            username = principal.getName();

            if (principal.getKeycloakSecurityContext().getIdToken() != null) {
                username =
                        principal.getKeycloakSecurityContext().getIdToken().getPreferredUsername();
            }
        } else {
            username = authentication.getPrincipal();
            details = authentication.getDetails();
        }

        this.authentication =
                new UsernamePasswordAuthenticationToken(
                        username, authentication.getCredentials(), authentication.getAuthorities());
        ((UsernamePasswordAuthenticationToken) this.authentication).setDetails(details);
        this.challenge = null;
    }

    /**
     * Execute the challenge to modify the response. The response should (upon success) contain
     * instructions on how to obtain valid credentials.
     *
     * @param request incoming request
     * @param response response to modify
     * @return does the response contain auth instructions?
     */
    public boolean challenge(HttpServletRequest request, HttpServletResponse response) {
        // if already authenticated, then there is nothing to do so consider this a success
        if (authentication != null) {
            return true;
        }
        // if no challenge exists and no creds are set, then this is FORBIDDEN
        if (challenge == null) {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            return false;
        }
        // otherwise, defer to the contained challenge
        return challenge.challenge(new SimpleHttpFacade(request, response));
    }

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException)
            throws IOException, ServletException {
        boolean challenged = challenge(request, response);
        // Only refused requests get here: one INFO line each, never the token or query string.
        if (authentication == null && LOG.isLoggable(Level.INFO)) {
            Object reason = request.getAttribute(FAILURE_REASON);
            String action = (challenged ? "challenged" : "refused") + " (" + response.getStatus() + ")";
            LOG.info(
                    "unauthenticated "
                            + clean(request.getMethod())
                            + " "
                            + clean(request.getRequestURI())
                            + " from "
                            + clean(clientAddress(request))
                            + ": "
                            + action
                            + ", "
                            + (reason != null ? reason : "no authentication"));
        }
    }

    /** The first X-Forwarded-For hop (the webserver proxies GeoServer), else the peer. */
    private static String clientAddress(HttpServletRequest request) {
        String fwd = request.getHeader("X-Forwarded-For");
        if (fwd != null && !fwd.trim().isEmpty()) {
            return fwd.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    /** No line breaks or control characters from the request in the log. */
    private static String clean(String value) {
        if (value == null) {
            return "-";
        }
        String v = value.replaceAll("[\\p{Cntrl}]", "_");
        return v.length() > 300 ? v.substring(0, 300) + "..." : v;
    }

    public Authentication getAuthentication() {
        return authentication;
    }

    public boolean hasAuthentication() {
        return authentication != null;
    }
}
