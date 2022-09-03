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
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sap.cloud.sdk.cloudplatform.connectivity.DestinationAccessor;
import com.sap.cloud.sdk.cloudplatform.connectivity.HttpClientAccessor;
import com.sap.cloud.sdk.cloudplatform.connectivity.HttpDestination;
import com.sap.cloud.sdk.cloudplatform.security.AuthToken;
import com.sap.cloud.sdk.cloudplatform.security.AuthTokenAccessor;

@WebServlet("/hello")
public class HelloWorldServlet extends HttpServlet
{
    private static final long serialVersionUID = 1L;
    private static final Logger logger = LoggerFactory.getLogger(HelloWorldServlet.class);
    private static ServiceLoader<IASTokenHeaderProvider> tokenHeaderLoader = ServiceLoader.load(IASTokenHeaderProvider.class);

    @Override
    protected void doGet( final HttpServletRequest request, final HttpServletResponse response )
        throws IOException
    {
        logger.info("Processing the request...");
        response.setContentType("text/plain");

        AuthToken xsuaaToken = AuthTokenAccessor.getCurrentToken();
        
        response.getWriter().append("Hello " + xsuaaToken.getJwt().getClaim("email").asString() + "\n");
        response.getWriter().append("Your IAS Token: " + xsuaaToken.getJwt().getToken() + "\n");
        
        // Step 5: Client Assertion Request
        HttpDestination tokenServiceDest = DestinationAccessor.getDestination("tokenService").asHttp();
        HttpClient client = HttpClientAccessor.getHttpClient(tokenServiceDest);
        URI uri = tokenServiceDest.getUri();
        HttpPost iasClientAssertionRequest = new HttpPost(uri);
        
        List<NameValuePair> params = new ArrayList<NameValuePair>();
        params.add(new BasicNameValuePair("grant_type", "client_credentials"));
        params.add(new BasicNameValuePair("resource", "urn:sap:identity:corporateidp"));
        iasClientAssertionRequest.setEntity(new UrlEncodedFormEntity(params));

        HttpResponse iasTokenExchangeResponse = client.execute(iasClientAssertionRequest);
        response.getWriter().append("Response code from Client Assertion request: " + iasTokenExchangeResponse.getStatusLine().getStatusCode());
        String body = IOUtils.toString(iasTokenExchangeResponse.getEntity().getContent(), "UTF-8");
        response.getWriter().append("Response body: " + body);

        // Step 6: BTP Application Token Request
        HttpDestination tokenExchangeDest = DestinationAccessor.getDestination("tokenExchange").asHttp();
        client = HttpClientAccessor.getHttpClient(tokenExchangeDest);
        uri = tokenExchangeDest.getUri();
        HttpPost iasTokenExchangeRequest = new HttpPost(uri);

        params = new ArrayList<NameValuePair>();
        params.add(new BasicNameValuePair("grant_type", "client_credentials"));
        params.add(new BasicNameValuePair("resource", "urn:sap:identity:corporateidp"));
        iasClientAssertionRequest.setEntity(new UrlEncodedFormEntity(params));


        // Step 7: Token Exchange BTP Application Token for Graph Token

        // Step 8: Call Graph API
    }
}