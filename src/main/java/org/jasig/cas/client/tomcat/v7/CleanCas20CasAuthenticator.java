package org.jasig.cas.client.tomcat.v7;

import java.io.IOException;
import java.util.regex.Pattern;

import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CleanCas20CasAuthenticator extends ValveBase {

    private final static Logger logger = LoggerFactory.getLogger(CleanCas20CasAuthenticator.class);
    Pattern filter = java.util.regex.Pattern.compile("ticket=[A-Za-z0-9\\.-]+");

    @Override
    public void invoke(Request request, Response response)
            throws IOException, ServletException {
        
        // Totally useless but without, POST data are swallowed
        @SuppressWarnings("unused")
        ServletInputStream postDataStream = request.getInputStream();

        if(request.getParameter("ticket") != null && "GET".equals(request.getMethod())) {
            String query = request.getQueryString();
            query = filter.matcher(query).replaceAll("");
            if(query.length() > 0) {
                query = "?" + query;
            }
            logger.debug("send redirect to {}{}", request.getRequestURI(), query);
            response.sendRedirect(response.encodeRedirectURL(request.getRequestURI() + query));
        } else {
            getNext().invoke(request, response);
        }

    }

}
