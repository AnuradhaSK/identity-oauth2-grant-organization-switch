package org.wso2.carbon.identity.oauth2.grant.organizationswitch;

import org.apache.commons.lang.ArrayUtils;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.grant.organizationswitch.internal.OrganizationSwitchGrantDataHolder;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.AuthenticationResult;
import org.wso2.carbon.user.core.constants.UserCoreClaimConstants;
import org.wso2.carbon.user.core.service.RealmService;

public class CustomPasswordGrant extends AbstractAuthorizationGrantHandler {

    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        super.validateGrant(tokReqMsgCtx);
        // Get accessing org.
        String accessingOrgId = extractParameter("org_id", tokReqMsgCtx);
        // Get username.
        String username = extractParameter("username", tokReqMsgCtx);
        // Get password.
        String password = extractParameter("password", tokReqMsgCtx);
        try {
            // Get userStoreManager of accessing org and authenticate the user in sub org level.
            String tenantDomainOfAccessingOrg = getOrganizationManager().resolveTenantDomain(accessingOrgId);
            AbstractUserStoreManager userStoreManager = getUserStoreManager(tenantDomainOfAccessingOrg);
            AuthenticationResult authenticationResult = userStoreManager.authenticateWithID(
                    UserCoreClaimConstants.USERNAME_CLAIM_URI, username, password,
                    UserCoreConstants.DEFAULT_PROFILE);
            boolean authenticated = AuthenticationResult.AuthenticationStatus.SUCCESS
                    == authenticationResult.getAuthenticationStatus()
                    && authenticationResult.getAuthenticatedUser().isPresent();
            if (authenticated) {
                AuthenticatedUser authenticatedUser =
                        new AuthenticatedUser(authenticationResult.getAuthenticatedUser().get());
                // Set accessing org.
                authenticatedUser.setAccessingOrganization(accessingOrgId);
                authenticatedUser.setUserResidentOrganization(accessingOrgId);
                tokReqMsgCtx.setAuthorizedUser(authenticatedUser);
                String[] allowedScopes = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope();
                tokReqMsgCtx.setScope(allowedScopes);
                return true;
            }
            throw new IdentityOAuth2Exception("Authentication failed for " + username);
        } catch (OrganizationManagementException | org.wso2.carbon.user.core.UserStoreException e) {
            throw new IdentityOAuth2Exception(e.getMessage());
        }
    }

    private OrganizationManager getOrganizationManager() {

        return OrganizationSwitchGrantDataHolder.getInstance().getOrganizationManager();
    }

    private AbstractUserStoreManager getUserStoreManager(String tenantDomain) throws IdentityOAuth2Exception {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        RealmService realmService = OrganizationSwitchGrantDataHolder.getInstance().getRealmService();
        AbstractUserStoreManager userStoreManager;
        try {
            userStoreManager =
                    (AbstractUserStoreManager) realmService.getTenantUserRealm(tenantId).getUserStoreManager();
        } catch (UserStoreException e) {
            throw new IdentityOAuth2Exception(e.getMessage(), e);
        }
        return userStoreManager;
    }

    private String extractParameter(String param, OAuthTokenReqMessageContext tokReqMsgCtx) {

        RequestParameter[] parameters = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();

        if (parameters != null) {
            for (RequestParameter parameter : parameters) {
                if (param.equals(parameter.getKey())) {
                    if (ArrayUtils.isNotEmpty(parameter.getValue())) {
                        return parameter.getValue()[0];
                    }
                }
            }
        }
        return null;
    }
}
