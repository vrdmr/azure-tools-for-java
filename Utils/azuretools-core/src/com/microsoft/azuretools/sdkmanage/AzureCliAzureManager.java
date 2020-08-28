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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.azure.auth.AzureAuthHelper;
import com.microsoft.azure.auth.AzureTokenWrapper;
import com.microsoft.azure.common.exceptions.AzureExecutionException;
import com.microsoft.azure.credentials.AzureCliCredentials;
import com.microsoft.azure.management.Azure;
import com.microsoft.azuretools.adauth.PromptBehavior;
import com.microsoft.azuretools.authmanage.AuthMethod;
import com.microsoft.azuretools.authmanage.AzureManagerFactory;
import com.microsoft.azuretools.authmanage.CommonSettings;
import com.microsoft.azuretools.authmanage.Environment;
import com.microsoft.azuretools.authmanage.models.AuthMethodDetails;
import com.microsoft.azuretools.azurecommons.helpers.NotNull;
import com.microsoft.azuretools.azurecommons.helpers.Nullable;
import com.microsoft.azuretools.utils.CommandUtils;
import com.microsoft.azuretools.utils.Pair;
import org.apache.commons.lang.ObjectUtils;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import static com.microsoft.azuretools.Constants.FILE_NAME_SUBSCRIPTIONS_DETAILS_AZ;
import static com.microsoft.azuretools.authmanage.Environment.ENVIRONMENT_LIST;

public class AzureCliAzureManager extends AzureManagerBase {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String FAILED_TO_AUTH_WITH_AZURE_CLI = "Failed to auth with Azure CLI";
    private static final String UNABLE_TO_GET_AZURE_CLI_CREDENTIALS = "Unable to get Azure CLI credentials, " +
            "please ensure you have installed Azure CLI and signed in.";
    public static final String CLI_TOKEN_PROP_ACCESS_TOKEN = "accessToken";
    public static final String CLI_TOKEN_FORMAT_ACCESSOR = "az.cmd account get-access-token -t %s";
    public static final String CLI_TOKEN_PROP_EXPIRATION = "expiresOn";

    protected Map<String, Pair<String, OffsetDateTime>> tenantTokens = new ConcurrentHashMap<>();

    private String defaultTenantId;
    private String defaultClientId;

    static {
        settings.setSubscriptionsDetailsFileName(FILE_NAME_SUBSCRIPTIONS_DETAILS_AZ);
    }

    @Override
    public String getAccessToken(String tid, String resource, PromptBehavior promptBehavior) throws IOException {
        if (!this.isSignedIn()) {
            return null;
        }
        Pair<String, OffsetDateTime> token = tenantTokens.computeIfAbsent(tid, this::getAccessTokenViaCli);
        final OffsetDateTime now = LocalDateTime.now().atZone(ZoneId.systemDefault()).toOffsetDateTime().withOffsetSameInstant(ZoneOffset.UTC);
        if (token.second().isBefore(now)) {
            token = this.getAccessTokenViaCli(tid);
            tenantTokens.put(tid, token);
        }
        return token.first();
    }

    /**
     * refer https://github.com/Azure/azure-sdk-for-java/blob/master/sdk/identity/azure-identity/src/main/java/com/azure/
     *       identity/implementation/IdentityClient.java#L366
     */
    private Pair<String, OffsetDateTime> getAccessTokenViaCli(String tid) {
        //
        final String command = String.format("az account get-access-token --output json -t %s", tid);
        final String jsonToken;
        try {
            jsonToken = CommandUtils.exec(command);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        final Map<String, Object> objectMap = convertJsonToMap(jsonToken);
        final String strToken = (String) objectMap.get(CLI_TOKEN_PROP_ACCESS_TOKEN);
        final String strTime = (String) objectMap.get(CLI_TOKEN_PROP_EXPIRATION);
        final String decoratedTime = String.join("T", strTime.substring(0, strTime.indexOf(".")).split(" "));
        final OffsetDateTime expiresOn = LocalDateTime.parse(decoratedTime, DateTimeFormatter.ISO_LOCAL_DATE_TIME)
                .atZone(ZoneId.systemDefault())
                .toOffsetDateTime().withOffsetSameInstant(ZoneOffset.UTC);
        return new Pair<>(strToken, expiresOn);
    }

    @Override
    public String getCurrentUserId() {
        return this.defaultClientId;
    }

    @Override
    protected String getDefaultTenantId() {
        return this.defaultTenantId;
    }

    @Override
    public void drop() throws IOException {
        this.defaultClientId = null;
        this.defaultTenantId = null;
        super.drop();
    }

    public boolean isSignedIn() {
        return Objects.nonNull(this.defaultTenantId) && Objects.nonNull(this.defaultClientId);
    }

    public AuthMethodDetails signIn() throws AzureExecutionException {
        try {
            AzureTokenWrapper azureTokenWrapper = AzureAuthHelper.getAzureCLICredential(null);
            if (azureTokenWrapper == null) {
                throw new AzureExecutionException(UNABLE_TO_GET_AZURE_CLI_CREDENTIALS);
            }
            final AzureCliCredentials credentials = (AzureCliCredentials) azureTokenWrapper.getAzureTokenCredentials();
            final Azure.Authenticated authenticated = Azure.configure().authenticate(credentials);
            if (authenticated == null) {
                throw new AzureExecutionException(FAILED_TO_AUTH_WITH_AZURE_CLI);
            }
            this.defaultClientId = credentials.clientId();
            this.defaultTenantId = authenticated.tenantId();
            final Environment environment = ENVIRONMENT_LIST.stream()
                    .filter(e -> ObjectUtils.equals(credentials.environment(), e.getAzureEnvironment()))
                    .findAny()
                    .orElse(Environment.GLOBAL);
            CommonSettings.setUpEnvironment(environment);

            final AuthMethodDetails authResult = new AuthMethodDetails();
            authResult.setAuthMethod(AuthMethod.AZ);
            authResult.setAzureEnv(credentials.environment().toString());
            return authResult;
        } catch (IOException e) {
            try {
                drop();
            } catch (IOException ignore) {
                // swallow exception while clean up
            }
            throw new AzureExecutionException(FAILED_TO_AUTH_WITH_AZURE_CLI, e);
        }
    }

    private static <V> Map<String, V> convertJsonToMap(@NotNull String jsonString) {
        try {
            return MAPPER.readValue(jsonString, new TypeReference<Map<String, V>>() {
            });
        } catch (Exception ignore) {
            return null;
        }
    }

    public static AzureCliAzureManager getInstance() {
        return LazyLoader.INSTANCE;
    }

    public static class AzureCliAzureManagerFactory implements AzureManagerFactory {

        @Override
        public @Nullable AzureManager factory(AuthMethodDetails authMethodDetails) {
            return getInstance().isSignedIn() ? getInstance() : null;
        }

        @Override
        public AuthMethodDetails restore(final AuthMethodDetails authMethodDetails) {
            try {
                getInstance().signIn();
            } catch (AzureExecutionException ignore) {
                // Catch the exception when restore
            }
            return authMethodDetails;
        }
    }

    private static class LazyLoader {
        static final AzureCliAzureManager INSTANCE = new AzureCliAzureManager();
    }
}
