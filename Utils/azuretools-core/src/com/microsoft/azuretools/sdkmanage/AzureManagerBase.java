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

import com.microsoft.azure.AzureEnvironment;
import com.microsoft.azure.arm.resources.AzureConfigurable;
import com.microsoft.azure.management.Azure;
import com.microsoft.azure.management.applicationinsights.v2015_05_01.implementation.InsightsManager;
import com.microsoft.azure.management.appplatform.v2019_05_01_preview.implementation.AppPlatformManager;
import com.microsoft.azure.management.resources.Subscription;
import com.microsoft.azure.management.resources.Tenant;
import com.microsoft.azuretools.authmanage.CommonSettings;
import com.microsoft.azuretools.authmanage.Environment;
import com.microsoft.azuretools.authmanage.RefreshableTokenCredentials;
import com.microsoft.azuretools.telemetry.TelemetryInterceptor;
import com.microsoft.azuretools.utils.Pair;
import org.apache.commons.lang3.StringUtils;
import rx.Observable;

import java.io.IOException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import static com.microsoft.azuretools.authmanage.Environment.*;

/**
 * Created by vlashch on 1/27/17.
 */
public abstract class AzureManagerBase implements AzureManager {
    private static final String CHINA_PORTAL = "https://portal.azure.cn";
    private static final String GLOBAL_PORTAL = "https://ms.portal.azure.com";

    private static final String CHINA_SCM_SUFFIX = ".scm.chinacloudsites.cn";
    private static final String GLOBAL_SCM_SUFFIX = ".scm.azurewebsites.net";

    protected Map<String, Azure> sidToAzureMap = new ConcurrentHashMap<>();
    protected Map<String, AppPlatformManager> sidToAzureSpringCloudManagerMap = new ConcurrentHashMap<>();
    protected Map<String, InsightsManager> sidToInsightsManagerMap = new ConcurrentHashMap<>();
    private static final Logger LOGGER = Logger.getLogger(AzureManagerBase.class.getName());

    @Override
    public String getPortalUrl() {
        Environment env = getEnvironment();
        if (GLOBAL.equals(env)) {
            return GLOBAL_PORTAL;
        } else if (CHINA.equals(env)) {
            return CHINA_PORTAL;
        } else if (GERMAN.equals(env)) {
            return AzureEnvironment.AZURE_GERMANY.portal();
        } else if (US_GOVERNMENT.equals(env)) {
            return AzureEnvironment.AZURE_US_GOVERNMENT.portal();
        } else {
            return env.getAzureEnvironment().portal();
        }
    }

    @Override
    public String getScmSuffix() {
        Environment env = getEnvironment();
        if (GLOBAL.equals(env)) {
            return GLOBAL_SCM_SUFFIX;
        } else if (CHINA.equals(env)) {
            return CHINA_SCM_SUFFIX;
        } else {
            return GLOBAL_SCM_SUFFIX;
        }
    }

    @Override
    public String getTenantIdBySubscription(String subscriptionId) throws IOException {
        final Pair<Subscription, Tenant> subscriptionTenantPair = getSubscriptionsWithTenant().stream()
                .filter(pair -> pair != null && pair.first() != null && pair.second() != null)
                .filter(pair -> StringUtils.equals(pair.first().subscriptionId(), subscriptionId))
                .findFirst().orElseThrow(() -> new IOException("Failed to find storage subscription id"));
        return subscriptionTenantPair.second().tenantId();
    }

    protected <T extends AzureConfigurable<T>> T buildAzureManager(AzureConfigurable<T> configurable) {
        return configurable.withInterceptor(new TelemetryInterceptor())
                .withUserAgent(CommonSettings.USER_AGENT);
    }

    protected abstract String getTenantId() throws IOException;

    @Override
    public List<Subscription> getSubscriptions() throws IOException {
        return getSubscriptionsWithTenant().stream().map(Pair::first).collect(Collectors.toList());
    }

    @Override
    public List<Pair<Subscription, Tenant>> getSubscriptionsWithTenant() throws IOException {
        final List<Pair<Subscription, Tenant>> subscriptions = new LinkedList<>();
        final Azure.Authenticated authentication = authTenant(getTenantId());
        // could be multi tenant - return all subscriptions for the current account
        final List<Tenant> tenants = getTenants(authentication);
        for (Tenant tenant : tenants) {
            final Azure.Authenticated tenantAuthentication = authTenant(tenant.tenantId());
            final List<Subscription> tenantSubscriptions = getSubscriptions(tenantAuthentication);
            for (Subscription subscription : tenantSubscriptions) {
                subscriptions.add(new Pair<>(subscription, tenant));
            }
        }
        return subscriptions;
    }

    protected List<Subscription> getSubscriptions(Azure.Authenticated tenantAuthentication) {
        return tenantAuthentication.subscriptions().listAsync()
                .onErrorResumeNext(err -> {
                    LOGGER.warning(err.getMessage());
                    return Observable.empty();
                })
                .toList()
                .toBlocking()
                .singleOrDefault(Collections.emptyList());
    }

    protected List<Tenant> getTenants(Azure.Authenticated authentication) {
        return authentication.tenants().listAsync()
                .onErrorResumeNext(err -> {
                    LOGGER.warning(err.getMessage());
                    return Observable.empty();
                })
                .toList()
                .toBlocking()
                .singleOrDefault(Collections.emptyList());
    }

    protected Azure.Authenticated authTenant(String tenantId) {
        return Azure.configure()
                .withInterceptor(new TelemetryInterceptor())
                .withUserAgent(CommonSettings.USER_AGENT)
                .authenticate(new RefreshableTokenCredentials(this, tenantId));
    }

    protected AppPlatformManager authSpringCloud(String subscriptionId, String tenantId) {
        return buildAzureManager(AppPlatformManager.configure())
                .authenticate(new RefreshableTokenCredentials(this, tenantId), subscriptionId);
    }

    protected InsightsManager authApplicationInsights(String subscriptionId, String tenantId) {
        return buildAzureManager(InsightsManager.configure())
                .authenticate(new RefreshableTokenCredentials(this, tenantId), subscriptionId);
    }
}
