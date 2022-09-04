package com.microsoft.samples;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sap.cloud.sdk.cloudplatform.ScpCfCloudPlatform;
import com.sap.cloud.sdk.cloudplatform.connectivity.DestinationAccessor;
import com.sap.cloud.sdk.cloudplatform.connectivity.HttpClientAccessor;
import com.sap.cloud.sdk.cloudplatform.connectivity.HttpDestination;
import com.sap.cloud.sdk.cloudplatform.security.AuthToken;
import com.sap.cloud.sdk.cloudplatform.security.AuthTokenAccessor;

@WebServlet("/debug")
public class DebugServlet extends HttpServlet
{
    private static final long serialVersionUID = 1L;
    private static final Logger logger = LoggerFactory.getLogger(DebugServlet.class);
    private static ServiceLoader<IASTokenHeaderProvider> tokenHeaderLoader = ServiceLoader.load(IASTokenHeaderProvider.class);

    private static final String AAD_IASAPP_CLIENTID = "ae6efb1b-2eac-4fc0-8028-cf1a25bd43e2";
    private static final String CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static final String AAD_DEMOAPP_CLIENT_ID = "7da45caf-51ea-412b-acf7-cc600e11e193";
    private static final String AAD_DEMOAPP_DEFAULT_SCOPE = "api://" + AAD_DEMOAPP_CLIENT_ID + "/.default";
    private static final String MSFT_GRAPH_DEFAULT_SCOPE = "https://graph.microsoft.com/.default";
    private static final String JWT_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    private static final String CLIENT_CREDENTIALS_GRANT_TYPE = "client_credentials";
    private static final String TOKEN_USE_OBO = "on_behalf_of";
    private static final String RESPONSE_TYPE_TOKEN = "token";

    @Override
    protected void doGet( final HttpServletRequest request, final HttpServletResponse response )
        throws IOException
    {
        logger.info("Processing the request...");
        response.setContentType("text/plain");

        AuthToken iasToken = AuthTokenAccessor.getCurrentToken();
        
        response.getWriter().append("Hello " + iasToken.getJwt().getClaim("email").asString());
        response.getWriter().append("\nYour IAS Token: " + iasToken.getJwt().getToken());
        
        // Step 5: Request Client Assertion from AAD to use it in the subsequent requests for the token exchange instead of a client secret
        HttpDestination iasTokenEndpointDest = DestinationAccessor.getDestination("iasTokenEndpoint").asHttp();
        HttpClient client = HttpClientAccessor.getHttpClient(iasTokenEndpointDest);
        URI iasTokenEndpointUri = iasTokenEndpointDest.getUri();
        HttpPost iasClientAssertionRequest = new HttpPost(iasTokenEndpointUri);        
        List<NameValuePair> params = new ArrayList<NameValuePair>();
        params.add(new BasicNameValuePair("grant_type", CLIENT_CREDENTIALS_GRANT_TYPE));
        params.add(new BasicNameValuePair("resource", "urn:sap:identity:corporateidp"));
        iasClientAssertionRequest.setEntity(new UrlEncodedFormEntity(params));

        HttpResponse iasClientAssertionResponse = client.execute(iasClientAssertionRequest);
        response.getWriter().append("\nResponse code from Client Assertion request: " + iasClientAssertionResponse.getStatusLine().getStatusCode());
        String body = IOUtils.toString(iasClientAssertionResponse.getEntity().getContent(), "UTF-8");
        response.getWriter().append("\nResponse body: " + body + "\n");        
        String clientAssertion = getAccessToken(body);

        // Step 6: Exchange the IAS ID token for AAD IAS (app) token via IAS OIDC Proxy        
        HttpDestination iasTokenExchangeDest = DestinationAccessor.getDestination("iasTokenExchange").asHttp();
        client = HttpClientAccessor.getHttpClient(iasTokenExchangeDest);
        URI iasTokenExchangeUri = iasTokenExchangeDest.getUri();
        HttpPost aadIASTokenRequest = new HttpPost(iasTokenExchangeUri);
        params = new ArrayList<NameValuePair>();
        params.add(new BasicNameValuePair("assertion", iasToken.getJwt().getToken()));
        JsonObject iasCredentials = ScpCfCloudPlatform.getInstanceOrThrow().getServiceCredentials("identity");
        String iasClientId = iasCredentials.get("clientid").getAsString();
        params.add(new BasicNameValuePair("client_id", iasClientId));
        params.add(new BasicNameValuePair("response_type", RESPONSE_TYPE_TOKEN));
        params.add(new BasicNameValuePair("scope", "api://7da45caf-51ea-412b-acf7-cc600e11e193/tokenexchange"));        
        aadIASTokenRequest.setEntity(new UrlEncodedFormEntity(params));
        HttpResponse aadIASTokenResponse = client.execute(aadIASTokenRequest);
        response.getWriter().append("\nResponse code from AAD IAS (app) Token Exchange request: " + aadIASTokenResponse.getStatusLine().getStatusCode());
        body = IOUtils.toString(aadIASTokenResponse.getEntity().getContent(), "UTF-8");
        response.getWriter().append("\nResponse body: " + body);
        String aadIASAccessToken = getAccessToken(body);

        // Step 6.1: Exchange AAD IAS token for AAD DemoApp Token via AAD token endpoint
        HttpDestination aadTokenEndpointDest = DestinationAccessor.getDestination("aadTokenEndpoint").asHttp();
        client = HttpClientAccessor.getHttpClient(aadTokenEndpointDest);
        URI aadTokenEndpointUri = aadTokenEndpointDest.getUri();
        HttpPost aadDemoAppTokenRequest = new HttpPost(aadTokenEndpointUri);
        params = new ArrayList<NameValuePair>();
        params.add(new BasicNameValuePair("grant_type", JWT_GRANT_TYPE));
        params.add(new BasicNameValuePair("client_id", AAD_IASAPP_CLIENTID));
        params.add(new BasicNameValuePair("client_assertion_type", CLIENT_ASSERTION_TYPE));
        params.add(new BasicNameValuePair("client_assertion", clientAssertion));
        params.add(new BasicNameValuePair("assertion", aadIASAccessToken));
        params.add(new BasicNameValuePair("scope", AAD_DEMOAPP_DEFAULT_SCOPE));
        params.add(new BasicNameValuePair("requested_token_use",TOKEN_USE_OBO));
        aadDemoAppTokenRequest.setEntity(new UrlEncodedFormEntity(params));
        HttpResponse aadDemoAppTokenResponse = client.execute(aadDemoAppTokenRequest);
        response.getWriter().append("\nResponse code from AAD DemoApp Token request: " + aadDemoAppTokenResponse.getStatusLine().getStatusCode());
        body = IOUtils.toString(aadDemoAppTokenResponse.getEntity().getContent(), "UTF-8");
        response.getWriter().append("\nResponse body: " + body);
        String aadDemoAppAccessToken = getAccessToken(body);

        // Step 7: Exchange AAD DemoApp Token for Microsoft Graph Token
        HttpPost graphTokenRequest = new HttpPost(aadTokenEndpointUri);
        params = new ArrayList<NameValuePair>();
        params.add(new BasicNameValuePair("assertion", aadDemoAppAccessToken));
        params.add(new BasicNameValuePair("client_assertion", clientAssertion));
        params.add(new BasicNameValuePair("client_assertion_type", CLIENT_ASSERTION_TYPE));
        params.add(new BasicNameValuePair("scope", MSFT_GRAPH_DEFAULT_SCOPE));
        params.add(new BasicNameValuePair("requested_token_use", TOKEN_USE_OBO));
        params.add(new BasicNameValuePair("client_id", AAD_DEMOAPP_CLIENT_ID));
        params.add(new BasicNameValuePair("response_type", RESPONSE_TYPE_TOKEN));
        params.add(new BasicNameValuePair("grant_type", JWT_GRANT_TYPE));
        graphTokenRequest.setEntity(new UrlEncodedFormEntity(params));
        HttpResponse graphTokenResponse = client.execute(graphTokenRequest);
        response.getWriter().append("\nResponse code from Graph token request: " + graphTokenResponse.getStatusLine().getStatusCode());
        body = IOUtils.toString(graphTokenResponse.getEntity().getContent(), "UTF-8");
        response.getWriter().append("\nResponse body: " + body);     
        String graphTokenAccessToken = getAccessToken(body);

        // Step 8: Call Graph API on behalf of the IAS-authenticated user with Microsoft Graph Token
        HttpDestination graphAPIEndpointDest = DestinationAccessor.getDestination("msftGraphEndpoint").asHttp();
        client = HttpClientAccessor.getHttpClient(graphAPIEndpointDest);
        URI graphAPIEndpointUri = graphAPIEndpointDest.getUri();
        HttpGet calendarEventsRequest = new HttpGet(graphAPIEndpointUri);

        calendarEventsRequest.addHeader("Authorization", "Bearer " + graphTokenAccessToken);
        HttpResponse calendarEventsResponse = client.execute(calendarEventsRequest);
        response.getWriter().append("\nResponse code from Calendar Events request: " + calendarEventsResponse.getStatusLine().getStatusCode());
        body = IOUtils.toString(calendarEventsResponse.getEntity().getContent(), "UTF-8");
        response.getWriter().append("\nResponse body: " + body);
    }

    private String getAccessToken(String jsonResponse) {
        JsonElement clientAssertionJson = JsonParser.parseString(jsonResponse);
        String accessToken = clientAssertionJson.getAsJsonObject().get("access_token").getAsString();
        return accessToken;
    }
}