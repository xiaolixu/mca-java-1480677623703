package wasdev.sample.servlet;
//package com.mcademo;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Logger;

public class OAuthServlet extends HttpServlet {
    // Define properties required for OAuth flows
    private static final Logger logger = Logger.getLogger(OAuthServlet.class.getName());
    
    private static final String clientId = "4b07cfe1-3875-419c-a0a2-8fb0a7b43dff";
    private static final String clientSecret = "MDlkYjZkYjAtOGVkOS00MjcxLWE5ZTMtMWNlODVhMDQ0MDUy";
    private static final String callbackUri = "http://mca-java.mybluemix.net/oauth/callback";
    private static final String authzEndpoint = "https://mobileclientaccess.ng.bluemix.net/oauth/v2/authorization";
    private static final String tokenEndpoint = "https://mobileclientaccess.ng.bluemix.net/oauth/v2/token";

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        logger.info("Incoming request :: " + request.getRequestURL() + "/" + request.getQueryString());
        logger.info("Redirecting to MCA for authorization");

        if (request.getRequestURI().contains("/login")){
            onLogin(request, response);
        } else if (request.getRequestURI().contains("/callback")){
            onCallback(request, response);
        } else if (request.getRequestURI().contains("/logout")){
            onLogout(request, response);
        } else {
            response.sendError(404, "Not Found");
        }
    }

    private void onLogin(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        logger.info("onLogin");
        String authzUrl = authzEndpoint + "?response_type=code";
        authzUrl += "&client_id=" + clientId;
        authzUrl += "&redirect_uri=" + callbackUri;
        response.sendRedirect(authzUrl);
    }


    private void onCallback(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        logger.info("onCallback");
        String grantCode = request.getQueryString().split("=")[1];

        JSONObject body = new JSONObject();
        try {
            body.put("grant_type", "authorization_code");
            body.put("client_id", clientId);
            body.put("redirect_uri", callbackUri);
            body.put("code", grantCode);
        } catch (Throwable t){}


        HttpPost req = new HttpPost(tokenEndpoint);
        String credentials = clientId + ":" + clientSecret;
        req.setHeader("Authorization", "Basic " + Base64.encodeBase64String(credentials.getBytes()));
        StringEntity entity = new StringEntity(body.toString(), ContentType.APPLICATION_JSON);
        req.setEntity(entity);

        CloseableHttpClient client = HttpClients.createDefault();
        CloseableHttpResponse resp = client.execute(req);
        String responseBodyString = EntityUtils.toString(resp.getEntity());

        JSONObject responseBodyJSON = new JSONObject(responseBodyString);

        String accessTokenBase64 = responseBodyJSON.getString("access_token");
        String idTokenBase64 = responseBodyJSON.getString("id_token");
        String idTokenBase64Payload = idTokenBase64.split("\\.")[1];

        byte[] idTokenDecodedPayload = new Base64(true).decodeBase64(idTokenBase64Payload);

        String idTokenDecodedPayloadString = new String(idTokenDecodedPayload);
        JSONObject idTokenJSON = new JSONObject(idTokenDecodedPayloadString);
        JSONObject userIdentity = idTokenJSON.getJSONObject("imf.user");

        JSONObject authData = new JSONObject();
        authData.put("accessToken", accessTokenBase64);
        authData.put("idToken", idTokenBase64);
        authData.put("userIdentity", userIdentity);

        request.getSession().setAttribute("mca", authData);

        resp.close();
        client.close();

        response.sendRedirect("/");
    }


    private void onLogout(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        logger.info("onLogout");
        request.getSession().setAttribute("mca", null);
        response.sendRedirect("/");
    }
}
