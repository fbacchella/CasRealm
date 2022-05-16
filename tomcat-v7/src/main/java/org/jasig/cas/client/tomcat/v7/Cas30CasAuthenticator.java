package org.jasig.cas.client.tomcat.v7;

import org.apache.catalina.LifecycleException;
import org.jasig.cas.client.validation.Cas30ServiceTicketValidator;
import org.jasig.cas.client.validation.TicketValidator;

public class Cas30CasAuthenticator extends AbstractCasAuthenticator {

    public static final String AUTH_METHOD = "CAS30";

    private static final String NAME = Cas30CasAuthenticator.class.getName();

    private Cas30ServiceTicketValidator ticketValidator;

    protected TicketValidator getTicketValidator() {
        return ticketValidator;
    }

    protected String getAuthenticationMethod() {
        return AUTH_METHOD;
    }

    protected String getName() {
        return NAME;
    }

    @Override
    protected void startInternal() throws LifecycleException {
        super.startInternal();
        ticketValidator = new Cas30ServiceTicketValidator(getCasServerUrlPrefix());
        if (getEncoding() != null) {
            ticketValidator.setEncoding(getEncoding());
        }
        ticketValidator.setProxyCallbackUrl(getProxyCallbackUrl());
        ticketValidator.setProxyGrantingTicketStorage(ProxyCallbackValve.getProxyGrantingTicketStorage());
        ticketValidator.setRenew(isRenew());
    }

}
