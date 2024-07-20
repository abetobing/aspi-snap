package io.abetobing.snap.core;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

public class SnapAspiUtils {
    /**
     * Generate string to sign for access token request
     * @param clientId oauth2 client id
     * @param timestamp current timestamp
     * @return string
     */
    public static String generateStringToSign(
        String clientId,
        String timestamp
    ) {
        return String.format("%s%s%s", clientId, Constants.SEPARATOR_PIPE, timestamp);
    }

    /**
     * generate string to sign for transactional request
     * @param requestMethod GET/POST/PUT
     * @param requestUri example: `/v1.0/account-inquiry-external`
     * @param requestBody example: `{"data":"string content"}`
     * @param accessToken oauth2 access token
     * @param timestamp current timestamp
     * @return composed string to be signed
     */
    public static String generateStringToSign(
        String requestMethod,
        String requestUri,
        String requestBody,
        String accessToken,
        String timestamp
    ) {
        return requestMethod +
            Constants.SEPARATOR_COLON +
            requestUri +
            Constants.SEPARATOR_COLON +
            accessToken +
            Constants.SEPARATOR_COLON +
            requestBody +
            Constants.SEPARATOR_COLON +
            timestamp;
    }

    /**
     * Generate X-TIMESTAMP value based on current time
     * @return timestamp on current datetime
     */
    public static String generateTimestamp() {
        final Instant instant = Instant.now() ;
        final ZoneId z = ZoneId.systemDefault();
        final DateTimeFormatter format = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'hh:mm:ss.SSSx");
        return instant.atZone(z).format(format);
    }

    /**
     * encode request body with SHA256 in hex encoded string
     *
     * @param requestBody the request body to be encoded
     * @return string encoded request body in hex encoding
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
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static PrivateKey privateKeyFromString(String input) {
        byte [] pkcs8EncodedBytes = Base64.getDecoder().decode(input);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static PublicKey publicKeyFromString(String input) {
        byte [] pkcs8EncodedBytes = Base64.getDecoder().decode(input);
        try {
            X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(pkcs8EncodedBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(X509publicKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * generate signature with HMAC_SHA512 algorithm.
     * @param stringToSign the content to be signed
     * @param secret secret key
     * @return string signature
     */
    public static String generateSignature(String stringToSign, String secret) {
        try {
            Mac mac = Mac.getInstance(Constants.HMAC_SHA512);
            SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Constants.HMAC_SHA512);
            mac.init(secretKeySpec);
            byte[] hash = mac.doFinal(stringToSign.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * generate signature with SHA256 RSA
     * @param stringToSign the content to be signed
     * @param privateKey private key
     * @return string signature
     */
    public static String generateSignature(String stringToSign, PrivateKey privateKey) {
        String result = null;
        try {
            Signature signature = Signature.getInstance(Constants.SHA256withRSA);
            signature.initSign(privateKey);
            signature.update(stringToSign.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = signature.sign();
            result = Base64.getEncoder().encodeToString(signatureBytes);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * Validate/compare given signature using public key
     * this method is to be used in pjp's side
     * @param givenSignature string containing signature to be compared
     * @param publicKey public key
     * @return true if signature is valid, false otherwise
     */
    public static boolean validateSignature(String stringToSign, String givenSignature, PublicKey publicKey) {
        try {
            byte[] givenSignatureBytes = Base64.getDecoder().decode(givenSignature);
            Signature expectedSignature = Signature.getInstance(Constants.SHA256withRSA);
            expectedSignature.initVerify(publicKey);
            expectedSignature.update(stringToSign.getBytes(StandardCharsets.UTF_8));
            return expectedSignature.verify(givenSignatureBytes);
        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return false;
    }
}
