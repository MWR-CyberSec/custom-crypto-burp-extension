package mwr.customcrypto;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.proxy.http.*;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.utilities.Base64Utils;
import burp.api.montoya.utilities.URLUtils;
import burp.api.montoya.utilities.Utilities;

import java.util.List;

public class CustomCrypto implements BurpExtension, ProxyRequestHandler, ProxyResponseHandler, HttpHandler {

    static Utilities utils;
    static Logging log;
    static PersistedObject storage;
    static Scope scope;

    static Base64Utils base64;

    static URLUtils url;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("MWR CyberSec Custom Crypto Template");

        api.proxy().registerRequestHandler(this);
        api.proxy().registerResponseHandler(this);
        api.http().registerHttpHandler(this);
        log = api.logging();
        utils = api.utilities();
        storage = api.persistence().extensionData();
        scope = api.scope();
        base64 = utils.base64Utils();
        url = utils.urlUtils();

        log.raiseInfoEvent("Custom Crypto extension loaded!");
        log.logToOutput("Custom Crypto extension loaded!");
        //storage.setByteArray("rsaPublicKey", base64.decode("MIIB..."));
        storage.setByteArray("rsaPrivateKey", base64.decode("""
                MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCuL9Yb8xsvKimy\
                lR/MJB2Z2oBXuIvIidHIVxf7+Sl3Y35sU53Vd+D1QOuJByvpLmpczYsQkUMJmKha\
                36ibC2gjBMlTlZJ0OwnjG+Na0libW9fnWZVKq0JuAhyJd9OUyO0Up1hk2W6/1abU\
                OuEcYn1CTdYrTq7pdRhKLp2kYfVo64oV+NPDgQWvaIyR9vdEA+tGa4bgm5BQENaw\
                0Uh6qrtBh8pFKDX9EMEizauhRAsOUVlZ6ZYWCiT+A+IGZHpzFIXWh0gRbIANDZAd\
                g+CATLT/jee9wi0Vvg7L4o/Xn293SIAXYK7NYEHwMZP/SSmtcasYSFfgFvZ3BX+j\
                OLNynG5lAgMBAAECggEABXwFGlEvwG7r7C8M1sEmW3NJSjnJ0PEh9VRksW7ZcuRj\
                lSaW2CNTpnU6VVCv/cIT4EMqh0WDnlg7qMzVAri7uSqL6kFR4K4BNDDrGi94Ub/1\
                Dtg/vp+g0lTnsB5hP5SJ/nX8bwR3m7uu6ozGDL4/ImjP/wIVuM0SjDdmiEf7UafX\
                iWE12Lq5RbsHnvcXte2wl09keRszatRk/ODrqMPxzjS1NSt6KBfxtiRPNB+GZt1y\
                DhYKaHEO0riDsUiXurMwt7bAlupiiIS0pDAfNDEnvc2gWaiir8pIFGezowd+sIOd\
                XSW3aJU2Y5ByroelgkovRNIpF2QPXfFSsHyzx5uQawKBgQDsnwAuzp07CaHrXyaJ\
                HBno149LOaGYzRucxdKFFndizY/Le7ONl4PujRV+dwATAnuo8WIz7Upitd1uuh+H\
                0n37G4gaKIPK0o/pNYgIpMAoWSRI9zkPyId8yBEcpMJiUYXhXziQHhYhJ3shzn/2\
                Rh5RDS31tCxykpe5AHATw+R60wKBgQC8c9bPRNakEftP4IkC5wriHXpwEXYWRmCf\
                rRmeJmfApUgGfnAWzWBu1D5eHZU5z+6iojSSyxZSGJfKedON6loySWww/ZF/1QqQ\
                xkS+E3S86jp1PeJVYu2DuYhfcb8AXjt4ed48DNEMR5XZeWIKCYLsACHmag1IR9cW\
                XmCgovO+5wKBgQDJaVp1fUfW3g8m07pwkSv4x6vgg3DrKQPtAXJ9+K6sun9A3M3s\
                o2EY6Jy4JkE47S8nkjheLQjZVybiPqniKik0Wq4SXhQ4y9zVzMw7V0l9zssVFONM\
                bQvvCjmOoSwZFn2YZj42ZnW9yOaF00mW7v6VTVumvrPq3p8pSZcdK+zLIwKBgQCm\
                qiwIEvFhGSYRdpq1nm/Zmgh2pHqzKHq7vPMzEvQfRA128Mtg3zGx0rN1uOQIxQRf\
                gOTODh4nbOiRgTy//crXPmgYy6iqTVeSwkZ5c+uCSAR7O8e3jE5SePtKreYmBTDD\
                U8Rfh1Y6bfTw6JD0H4VSAqv4g0JL8n0eo0kByBuZcQKBgGdaG1XJZbK4a1fQ3scR\
                sv8Z+HgkaKS1FY0nXShNwFaE4Tfk6f/gsTgNqbyhk+HsFelmxKoFgf0Sa7313TPR\
                ibFr+wDYJVOApLm9P/dg5AecXRylUKv/gbbVwBDnkCWrm48H3MY+uLqVBUZ+2jfi\
                c7A3LDsSigmnDbODU4muEM0Z"""));
        //storage.setByteArray("aesSecretkey", base64.decode("..."));
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        HttpRequest updatedRequest = interceptedRequest;
        ByteArray decryptedBody;
        String data = null, mac = null, sign = null;

        if (!scope.isInScope(interceptedRequest.url()))
            return null;
        log.logToOutput("Processing incoming request for: " + interceptedRequest.url());

        List<ParsedHttpParameter> params = interceptedRequest.parameters();
        //List<HttpHeader> headers = interceptedRequest.headers();
        //ByteArray body = interceptedRequest.body();

        for (ParsedHttpParameter param : params) {
            if (param.type() != HttpParameterType.BODY)
                continue;
            if (param.name().equals("data"))
                data = url.decode(param.value());
            if (param.name().equals("mac"))
                mac = url.decode(param.value());
            if (param.name().equals("sign"))
                sign = url.decode(param.value());
        }
        if (mac == null || data == null)
            return null;

        //Here we save the mac to a header, as it is unique to the request and will be lost once we update it
        //we can also use comments, but I'd rather save those for the user
        //we can also use persistence, but since these are unique per request, that could cause concurrency issues
        updatedRequest = updatedRequest.withAddedHeader("X-Request-Mac", mac);

        updatedRequest = updatedRequest.withAddedHeader("X-Is-Signed", String.valueOf(sign != null));

        decryptedBody = CryptoOperations.AES.decryptWithCbcPkcs5(
                base64.decode(data),
                base64.decode(CryptoOperations.rot(mac, 13)),
                ByteArray.byteArray("0000000000000000")
        );

        updatedRequest = updatedRequest.withBody(decryptedBody);
        //updatedRequest = updatedRequest.withUpdatedParameters();
        //updatedRequest = updatedRequest.withUpdatedHeader();

        return ProxyRequestReceivedAction.continueWith(updatedRequest);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        return null;
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        return null;
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        HttpResponse updatedResponse = interceptedResponse;
        HttpRequest initiatingRequest = interceptedResponse.initiatingRequest();
        ByteArray body = interceptedResponse.body();
        String mac = null;

        if (!scope.isInScope(initiatingRequest.url()))
            return null;
        log.logToOutput("Processing outgoing response for: " + interceptedResponse.initiatingRequest().url());

        List<HttpHeader> headers = initiatingRequest.headers();
        for (HttpHeader header : headers) {
            if (header.name().equals("X-Request-Mac"))
                mac = header.value();
        }
        if (mac == null) {
            log.logToOutput("Could not get MAC for outgoing request");
            return null;
        }

        ByteArray data = CryptoOperations.AES.encryptWithCbcPkcs5(
                body,
                base64.decode(CryptoOperations.rot(mac, 13)),
                ByteArray.byteArray("0000000000000000")
        );
        updatedResponse = updatedResponse.withBody("result=" + url.encode(base64.encode(data)));
        return ProxyResponseToBeSentAction.continueWith(updatedResponse);
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
        HttpRequest updatedRequest = httpRequestToBeSent;
        ByteArray savedBody = httpRequestToBeSent.body();
        List<HttpHeader> headers = httpRequestToBeSent.headers();
        ByteArray encryptedData;
        String mac = null;
        Boolean isSigned = false;

        if (!scope.isInScope(httpRequestToBeSent.url()))
            return null;
        log.logToOutput("Processing outgoing request for: " + httpRequestToBeSent.url());

        for (HttpHeader header : headers) {
            if (header.name().equals("X-Is-Signed"))
                isSigned = Boolean.parseBoolean(header.value());
            else if (header.name().equals("X-Request-Mac"))
                mac = header.value();
        }
        if (mac == null) {
            log.logToOutput("Could not get MAC for outgoing request");
            return null;
        }

        encryptedData = CryptoOperations.AES.encryptWithCbcPkcs5(
                savedBody,
                base64.decode(CryptoOperations.rot(mac, 13)),
                ByteArray.byteArray("0000000000000000")
        );
        updatedRequest = updatedRequest.withBody("");

        updatedRequest = updatedRequest.withAddedParameters(
                HttpParameter.bodyParameter("mac", url.encode(mac)),
                HttpParameter.bodyParameter("data", url.encode(base64.encodeToString(encryptedData)))
        );

        if (isSigned) {
            ByteArray signature = CryptoOperations.RSA.signWithSha256(savedBody, null);
            updatedRequest = updatedRequest.withAddedParameters(HttpParameter.bodyParameter("sign", url.encode(base64.encodeToString(signature))));
        }
        updatedRequest = updatedRequest.withRemovedHeader("X-Is-Signed");
        updatedRequest = updatedRequest.withRemovedHeader("X-Request-Mac");
        return RequestToBeSentAction.continueWith(updatedRequest);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        HttpResponse updatedResponse = httpResponseReceived;
        HttpRequest initiatingRequest = httpResponseReceived.initiatingRequest();
        ByteArray decryptedBody;
        String mac = null;

        if (!scope.isInScope(initiatingRequest.url()))
            return null;
        log.logToOutput("Processing incoming response for: " + initiatingRequest.url());

        ByteArray body = httpResponseReceived.body();

        List<ParsedHttpParameter> params = initiatingRequest.parameters();
        for (ParsedHttpParameter param : params) {
            if (param.type() != HttpParameterType.BODY)
                continue;
            if (param.name().equals("mac"))
                mac = url.decode(param.value());
        }
        if (mac == null) {
            log.logToOutput("Could not get MAC for incoming response");
            return null;
        }

        decryptedBody = CryptoOperations.AES.decryptWithCbcPkcs5(
                //The sub-array here is to remove the first 7 characters ("result=")
                base64.decode(url.decode(body.subArray(7, body.length()))),
                base64.decode(CryptoOperations.rot(mac, 13)),
                ByteArray.byteArray("0000000000000000")
        );

        updatedResponse = updatedResponse.withBody(decryptedBody);
        return ResponseReceivedAction.continueWith(updatedResponse);
    }
}