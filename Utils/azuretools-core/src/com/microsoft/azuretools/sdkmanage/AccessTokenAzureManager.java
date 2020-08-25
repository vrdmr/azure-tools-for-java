/*
 * Copyright (c) Microsoft Corporation
 *
 * All rights reserved.
 *
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
 * to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of
 * the Software.
 *
 * THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.microsoft.azuretools.sdkmanage;

import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import com.microsoft.azure.management.Azure;
import com.microsoft.azure.management.applicationinsights.v2015_05_01.implementation.InsightsManager;
import com.microsoft.azure.management.appplatform.v2019_05_01_preview.implementation.AppPlatformManager;
import com.microsoft.azuretools.adauth.PromptBehavior;
import com.microsoft.azuretools.adauth.StringUtils;
import com.microsoft.azuretools.authmanage.AdAuthManagerBuilder;
import com.microsoft.azuretools.authmanage.AzureManagerFactory;
import com.microsoft.azuretools.authmanage.BaseADAuthManager;
import com.microsoft.azuretools.authmanage.CommonSettings;
import com.microsoft.azuretools.authmanage.Environment;
import com.microsoft.azuretools.authmanage.SubscriptionManager;
import com.microsoft.azuretools.authmanage.SubscriptionManagerPersist;
import com.microsoft.azuretools.authmanage.models.AuthMethodDetails;
import com.microsoft.azuretools.utils.AzureRegisterProviderNamespaces;
import com.microsoft.rest.credentials.ServiceClientCredentials;

import java.io.IOException;

import static com.microsoft.azuretools.Constants.FILE_NAME_SUBSCRIPTIONS_DETAILS_AT;
import static org.apache.commons.lang3.StringUtils.isBlank;

public class AccessTokenAzureManager extends AzureManagerBase {
    public static class AccessTokenAzureManagerFactory implements AzureManagerFactory, AdAuthManagerBuilder {
        private final BaseADAuthManager adAuthManager;

        public AccessTokenAzureManagerFactory(final BaseADAuthManager adAuthManager) {
            this.adAuthManager = adAuthManager;
        }

        @Override
        public AzureManager factory(final AuthMethodDetails authMethodDetails) {
            if (isBlank(authMethodDetails.getAccountEmail())) {
                throw new IllegalArgumentException(
                        "No account email provided to create Azure manager for access token based authentication");
            }

            adAuthManager.applyAuthMethodDetails(authMethodDetails);
            return new AccessTokenAzureManager(adAuthManager);
        }

        @Override
        public AuthMethodDetails restore(AuthMethodDetails authMethodDetails) {
            if (!StringUtils.isNullOrEmpty(authMethodDetails.getAccountEmail())
                    && !adAuthManager.tryRestoreSignIn(authMethodDetails)) {
                return new AuthMethodDetails();
            }

            return authMethodDetails;
        }

        @Override
        public BaseADAuthManager getInstance() {
            return adAuthManager;
        }
    }

    private final SubscriptionManager subscriptionManager;
    private final BaseADAuthManager delegateADAuthManager;

    public AccessTokenAzureManager(final BaseADAuthManager delegateADAuthManager) {
        this.delegateADAuthManager = delegateADAuthManager;
        this.subscriptionManager = new SubscriptionManagerPersist(this);
    }

    @Override
    public SubscriptionManager getSubscriptionManager() {
        return subscriptionManager;
    }

    @Override
    public void drop() throws IOException {
        subscriptionManager.cleanSubscriptions();
        delegateADAuthManager.signOut();
    }

    private static Settings settings;

    static {
        settings = new Settings();
        settings.setSubscriptionsDetailsFileName(FILE_NAME_SUBSCRIPTIONS_DETAILS_AT);
    }

    @Override
    public Azure getAzure(String sid) throws IOException {
        if (sidToAzureMap.containsKey(sid)) {
            return sidToAzureMap.get(sid);
        }
        String tid = subscriptionManager.getSubscriptionTenant(sid);
        Azure azure = authTenant(tid).withSubscription(sid);
        // TODO: remove this call after Azure SDK properly implements handling of unregistered provider namespaces
        AzureRegisterProviderNamespaces.registerAzureNamespaces(azure);
        sidToAzureMap.put(sid, azure);
        return azure;
    }

    @Override
    public AppPlatformManager getAzureSpringCloudClient(String sid) {
        return sidToAzureSpringCloudManagerMap.computeIfAbsent(sid, s -> {
            String tid = subscriptionManager.getSubscriptionTenant(sid);
            return authSpringCloud(sid, tid);
        });
    }

    @Override
    public InsightsManager getInsightsManager(String sid) {
        return sidToInsightsManagerMap.computeIfAbsent(sid, s -> {
            String tid = subscriptionManager.getSubscriptionTenant(sid);
            return authApplicationInsights(sid, tid);
        });
    }

    @Override
    public Settings getSettings() {
        return settings;
    }

    @Override
    protected String getTenantId() {
        return delegateADAuthManager.getCommonTenantId();
    }

    @Override
    public KeyVaultClient getKeyVaultClient(String tid) {
        ServiceClientCredentials creds = new KeyVaultCredentials() {
            @Override
            public String doAuthenticate(String authorization, String resource, String scope) {
                try {
                    // TODO: check usage
                    return delegateADAuthManager.getAccessToken(tid, resource, PromptBehavior.Auto);
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            }
        };
        return new KeyVaultClient(creds);
    }

    @Override
    public String getCurrentUserId() throws IOException {
        return delegateADAuthManager.getAccountEmail();
    }

    @Override
    public String getAccessToken(String tid, String resource, PromptBehavior promptBehavior) throws IOException {
        return delegateADAuthManager.getAccessToken(tid, resource, promptBehavior);
    }

    @Override
    public String getManagementURI() throws IOException {
        // environments other than global cloud are not supported for interactive login for now
        return CommonSettings.getAdEnvironment().resourceManagerEndpoint();
    }

    public String getStorageEndpointSuffix() {
        return CommonSettings.getAdEnvironment().storageEndpointSuffix();
    }

    @Override
    public Environment getEnvironment() {
        return CommonSettings.getEnvironment();
    }

}
