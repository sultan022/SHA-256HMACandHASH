package abc;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Formatter;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CreateSignature {

	
	private static String entity_digest="";
	private static String body="<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><test><country>NL</country><merchant-id>yourmerchantID</merchant-id><merchant-request-id>12_gctest</merchant-request-id></test>";
	
	private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
	private static final String SHA256_ALGORITHM = "SHA-256";
	
	private static String messageToSign="POST /whatever/1.0/method-optin\n" + 
			"Content-Type: application/xml; charset=UTF-8\n" + 
			"853dc50ae69e8ea56857a4942e46879387ef2175834a481cbb9b1373c1d24cad\n" + 
			"1563266580";
	
	public static void main (String [] args) {
		
	
		
		String hmac="";
		try {
			
			//calculate digest  code here
			entity_digest = calculateDigest(body);
			
			System.out.println("Hex Encoded HASH "+entity_digest);
			
			
			//calculate hmac code here 
			
			hmac = calculateHmac(messageToSign, "$YOURapiSecKey$");
		} catch (Exception e) {
			e.printStackTrace();
		
		}
		
		System.out.println("Hex Encoded HMAC "+hmac);
				
	}
	
	
	public static String calculateDigest(String data) throws Exception {
		
		MessageDigest digest = MessageDigest.getInstance(SHA256_ALGORITHM);
		byte[] encodedhash = digest.digest(
				data.getBytes("UTF-8"));
		return toHexString(encodedhash);
		
		

	}
	
	public static String calculateHmac(String data, String key)
			throws SignatureException, NoSuchAlgorithmException, InvalidKeyException
		{
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
