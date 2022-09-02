package com.microsoft.samples;

import java.util.Base64;
import java.util.Collections;
import java.util.List;

import javax.annotation.Nonnull;

import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.impl.auth.BasicScheme;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.JsonObject;
import com.sap.cloud.sdk.cloudplatform.ScpCfCloudPlatform;
import com.sap.cloud.sdk.cloudplatform.connectivity.DestinationHeaderProvider;
import com.sap.cloud.sdk.cloudplatform.connectivity.DestinationRequestContext;
import com.sap.cloud.sdk.cloudplatform.connectivity.Header;

public class IASTokenHeaderProvider implements DestinationHeaderProvider {

    private static final Logger logger = LoggerFactory.getLogger(HelloWorldServlet.class);

    @Nonnull
    @Override
    public List<Header> getHeaders( @Nonnull final DestinationRequestContext requestContext )
    {
        final Header header;
        if (requestContext.getDestination().get("name").contains("tokenService")) {
            logger.debug("Adding authz header for IAS request");
            header = new Header("Authorization", obtainIASCredentials());    
            return Collections.singletonList(header);
        } else 
            return null;
    }   
    
    private String obtainIASCredentials()
    {
        JsonObject iasCredentials = ScpCfCloudPlatform.getInstanceOrThrow().getServiceCredentials("identity");
        String iasclientid = iasCredentials.get("clientid").getAsString();
        String iasclientSecret = iasCredentials.get("clientsecret").getAsString();       
        String basicCredentials = String.format("%s:%s", iasclientid, iasclientSecret);
        return String.format("Basic %s", Base64.getEncoder().encodeToString(basicCredentials.getBytes()));
    }
}
