package io.abetobing.snap;

import org.apache.hc.core5.http.EntityDetails;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpRequestInterceptor;
import org.apache.hc.core5.http.protocol.HttpContext;

import java.io.IOException;

public class HttpClientSnapRequestInterceptor implements HttpRequestInterceptor {
    @Override
    public void process(
        HttpRequest request, EntityDetails entityDetails, HttpContext context
    ) throws HttpException, IOException {
//        String signature = generateSignature();
//        request.addHeader("X-SIGNATURE", signature);
    }
}
