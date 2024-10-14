package org.wso2.carbon.identity.oauth2.grant.organizationswitch;

import org.apache.oltu.oauth2.common.validators.AbstractValidator;

import javax.servlet.http.HttpServletRequest;

public class CustomPasswordGrantValidator extends AbstractValidator<HttpServletRequest> {

    public CustomPasswordGrantValidator() {

        requiredParams.add("org_id");
        requiredParams.add("username");
        requiredParams.add("password");
    }
}
