package com.example.auth.web;

import java.io.IOException;
import java.io.PrintWriter;
import jakarta.servlet.http.HttpServletResponse;

/** Response plumbing shared by the auth endpoints. */
final class Responses {

    private Responses() {
    }

    /**
     * Auth pages and auth errors must not be cached: a cached sign-in page on a shared machine is a
     * handed-over session, and a cached refusal tells a proxy which attempts failed.
     */
    static void doNotCache(HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        response.setDateHeader("Expires", 0L);
    }

    static void html(HttpServletResponse response, int status, String bodyHtml) throws IOException {
        doNotCache(response);
        response.setStatus(status);
        response.setContentType("text/html;charset=UTF-8");
        try (PrintWriter out = response.getWriter()) {
            out.print("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n");
            out.print("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
            out.print("<title>" + Html.escape(pageTitle(bodyHtml)) + "</title>\n");
            out.print(STYLE + "</head>\n<body>\n" + bodyHtml + "\n</body>\n</html>\n");
        }
    }

    static void json(HttpServletResponse response, int status, String bodyJson) throws IOException {
        doNotCache(response);
        response.setStatus(status);
        response.setContentType("application/json;charset=UTF-8");
        response.setHeader("X-Content-Type-Options", "nosniff");
        try (PrintWriter out = response.getWriter()) {
            out.print(bodyJson);
        }
    }

    /** The first {@code <h1>} of the page, used as its title. */
    private static String pageTitle(String bodyHtml) {
        int start = bodyHtml.indexOf("<h1>");
        if (start < 0) {
            return "Sign in";
        }
        int end = bodyHtml.indexOf("</h1>", start);
        return end < 0 ? "Sign in" : bodyHtml.substring(start + 4, end);
    }

    private static final String STYLE = """
            <style>
            body{font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0 auto;max-width:38rem;padding:2rem 1rem;color:#1b1b1b;background:#fff}
            h1{font-size:1.4rem;margin-bottom:.25rem}
            p.lead{color:#555;margin-top:0}
            form{margin:1.25rem 0}
            label{display:block;margin:.75rem 0 .25rem;font-weight:600}
            input[type=text],input[type=password]{width:100%;padding:.5rem;font:inherit;border:1px solid #bbb;border-radius:4px;box-sizing:border-box}
            input[type=submit]{margin-top:1rem;padding:.55rem 1.1rem;font:inherit;font-weight:600;border:1px solid #333;border-radius:4px;background:#1b1b1b;color:#fff;cursor:pointer}
            .field{display:flex;align-items:center;gap:.4rem;font-weight:400;margin-top:.75rem}
            .field input{width:auto}
            .error{padding:.6rem .8rem;border-left:4px solid #b00020;background:#fff2f2;color:#7a0014;margin:1rem 0}
            .note{padding:.6rem .8rem;background:#f4f4f5;border-left:4px solid #888;font-size:.9rem}
            code{background:#f4f4f5;padding:.1rem .3rem;border-radius:3px}
            ul{padding-left:1.2rem}
            a{color:#0b5cad}
            </style>
            """;
}
