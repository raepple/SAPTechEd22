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
        response.getWriter().append("Your XSUAA Token: " + xsuaaToken.getJwt().getToken() + "\n");
        
        HttpDestination tokenServiceDest = DestinationAccessor.getDestination("tokenService").asHttp();
        HttpClient client = HttpClientAccessor.getHttpClient(tokenServiceDest);
        URI uri = tokenServiceDest.getUri();
        HttpPost iasTokenExchangeRequest = new HttpPost(uri);
        
        List<NameValuePair> params = new ArrayList<NameValuePair>();
        params.add(new BasicNameValuePair("grant_type", "client_credentials"));
        params.add(new BasicNameValuePair("resource", "urn:sap:identity:corporateidp"));
        iasTokenExchangeRequest.setEntity(new UrlEncodedFormEntity(params));

        HttpResponse iasTokenExchangeResponse = client.execute(iasTokenExchangeRequest);
        response.getWriter().append("Response from Client Assertion request: " + iasTokenExchangeResponse.getStatusLine().getStatusCode());
    }
}