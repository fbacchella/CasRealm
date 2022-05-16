package org.jasig.cas.client.tomcat.common;

import java.io.IOException;
import java.util.Map;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CleanUrl {

    private static final Pattern filter = Pattern.compile("(ticket|SAMLart)=[A-Za-z0-9\\.-]+");

    private boolean doRequest(String method, Map<String, String[]> params) {
        // GET must be checked first, because request.getParameter with POST query can make a mess of InputStream
        return "GET".equals(method) &&
                (params.containsKey("ticket") || params.containsKey("SAMLart"));
    }

    public boolean invoke(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (doRequest(request.getMethod(), request.getParameterMap())) {
            String query = filter.matcher(request.getQueryString()).replaceAll("");
            if(query.length() > 0) {
                query = "?" + query;
            }
            response.sendRedirect(response.encodeRedirectURL(request.getRequestURI() + query));
            return true;
        } else {
            return false;
        }
    }

}
