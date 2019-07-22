package com.globalcharge.security;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Formatter;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;

public class CreateSignature {

	private static String entity_digest = "";
	private static String key = "L1gGied7a538JDCvtNx2q6Mpy30b2OTbNCrmxCw5Zw8XlJmWpaq8TXfmqWgornSXZE4RwkzCznrYb01gKhzkLXurainuB0bba9Pz";
	private static String body="<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><optin-request><country>NL</country><merchant-id>gc_badoo</merchant-id><merchant-request-id>1</merchant-request-id><msisdn>14155551234</msisdn><optin-type>otp</optin-type><otp><network mcc=\"204\" mnc=\"08\" name=\"KPN Telecom\" /></otp></optin-request>";
	private static String messageToSign = "POST /optin/3.0/optin\n" + 
			"Content-Type: application/xml; charset=UTF-8\n" + 
			"bc548cc84dc1967342a89b1ea929bed2392ccf2cc9b954feb694fa8dc068191a\n" + 
			"1563802336";

	private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
	private static final String SHA256_ALGORITHM = "SHA-256";

	
	public static void main(String[] args) {

		String hmac = "";
		try {

			System.out.println("Current Timestamp is "+System.currentTimeMillis() / 1000L);
			
			
			// calculate digest code here
			entity_digest = calculateDigest(body);

			System.out.println("Hex Encoded ENTITY Digest " + entity_digest);
			
			// signature generation code here

			hmac = generateSignatureNewMethod(key, messageToSign);

			System.out.println("Hex Encoded HMAC SIGNATURE "+hmac);
		} catch (Exception e) {
			e.printStackTrace();

		}


	}

	public static String generateSignatureNewMethod(final String key, final String data)
			throws Exception {
		
		
		Mac sha256_HMAC = Mac.getInstance(HMAC_SHA256_ALGORITHM);
		SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), HMAC_SHA256_ALGORITHM);
		sha256_HMAC.init(secretKey);
		byte[] hash = sha256_HMAC.doFinal(data.getBytes("UTF-8"));
		char[] check = Hex.encodeHex(hash);
		return new String(check);
		
		
	}

	public static String calculateDigest(String data) throws Exception {

		MessageDigest digest = MessageDigest.getInstance(SHA256_ALGORITHM);
		byte[] encodedhash = digest.digest(data.getBytes("UTF-8"));
		return toHexString(encodedhash);

	}

	public static String calculateHmac(String data, String key)
			throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
		SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA256_ALGORITHM);
		Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
		mac.init(signingKey);
		return toHexString(mac.doFinal(data.getBytes()));
	}

	private static String toHexString(byte[] bytes) {
		Formatter formatter = new Formatter();

		for (byte b : bytes) {
			formatter.format("%02x", b);
		}

		return formatter.toString();
	}

}
