package com.example.auth.web;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;

/**
 * Builds the {@link AuthContext} when the application is deployed and shuts the session store down
 * when it is undeployed, so the reaper thread does not outlive the web application.
 */
@WebListener
public class AuthContextListener implements ServletContextListener {

    @Override
    public void contextInitialized(ServletContextEvent event) {
        AuthContext.install(event.getServletContext());
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        try {
            AuthContext.of(event.getServletContext()).sessions().shutdown();
        } catch (IllegalStateException alreadyGone) {
            // The context never finished installing; there is nothing to shut down.
        }
    }
}
