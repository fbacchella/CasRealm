package org.jasig.cas.client.tomcat.v90;

import java.io.IOException;

import javax.servlet.ServletException;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.jasig.cas.client.tomcat.common.CleanUrl;

public class CleanCasAuthenticator extends ValveBase {

    private final CleanUrl cleaner = new CleanUrl();

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        if (! cleaner.invoke(request, response)) {
            getNext().invoke(request, response);
        }
    }

}
