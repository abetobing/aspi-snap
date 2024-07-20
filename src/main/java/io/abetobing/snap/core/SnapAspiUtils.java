package io.abetobing.snap.core;

import org.apache.hc.core5.http.NotImplementedException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public class SnapAspiUtils {
    /**
     * Generate string to sign for access token request
     * @param clientId
     * @param timestamp
     * @return
     */
    public static String generateStringToSign(
        String clientId,
        String timestamp
    ) {
        return String.format("%s%s%s", clientId, Constants.SEPARATOR_PIPE, timestamp);
    }

    /**
     * generate string to sign for transactional request
     * @param requestMethod
     * @param requestUri
     * @param requestBody
     * @param accessToken
     * @param timestamp
     * @return
     */
    public static String generateStringToSign(
        String requestMethod,
        String requestUri,
        String requestBody,
        String accessToken,
        String timestamp
    ) {
        final StringBuilder builder =  new StringBuilder();
        builder.append(requestMethod)
            .append(Constants.SEPARATOR_COLON)
            .append(requestUri)
            .append(Constants.SEPARATOR_COLON)
            .append(accessToken)
            .append(Constants.SEPARATOR_COLON)
            .append(requestBody)
            .append(Constants.SEPARATOR_COLON)
            .append(timestamp);
        return builder.toString();
    }

    /**
     * Generate X-TIMESTAMP value based on current time
     * @return
     */
    public static String generateTimestamp() {
        final Instant instant = Instant.now() ;
        final ZoneId z = ZoneId.systemDefault();
        final DateTimeFormatter format = DateTimeFormatter.ofPattern("yyyy-mm-dd'T'hh:mm:ss.SSSx");
        return instant.atZone(z).format(format);
    }

    /**
     * encode request body with SHA256 in hex encoded string
     *
     * @param requestBody
     * @return
     */
    public static String encodeRequestBody(String requestBody) {
        String encodedBody = null;
        try {
            MessageDigest digest = MessageDigest.getInstance(Constants.SHA256);
            byte[] hash = digest.digest(requestBody.getBytes(StandardCharsets.UTF_8));
            encodedBody = bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return encodedBody;
    }

    private static String bytesToHex(byte[] hash) {
        final StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static String generateSignature(String stringToSign, String secret) {
        //TODO: implement this
        return null;
    }

    public static String generateSignature(String stringToSign, PrivateKey privateKey) {
        //TODO: implement this
        return null;
    }
}
