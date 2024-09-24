import java.net.URLDecoder;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.Cipher;
import java.security.Key ;
import java.security.KeyPair ;

public class SecuredRSAUUsageNew {

    static int RSA_KEY_LENGTH = 4096;
    static String ALGORITHM_NAME = "RSA" ;
    static String PADDING_SCHEME = "PKCS1Padding" ;
    static String MODE_OF_OPERATION = "ECB" ; // This essentially means none behind the scene

    public static void main(String[] args) {
        String shortMessage = "TEST123" ;
        String encryptedText = "sJ3OIIoyL2TaQ1KL6UvY63YNPSkdw6VS3%2FDexKLO%2Fw2K3u5btF2ylQEWHPKOMS39Q%2F3iSz9eccldM63QjDtUiFHyT8ZJ%2FchXHsZYCPP0A6X%2Fi4XCHID%2BreAjN%2F0aaz1kr%2FFhvhw1gF9Ig89O3ZTHy4N3VN08Ap8KLVURvYQmwgPZtH3y28zAywcS40PaaENbBhPWMIXLr%2BIXkbjTtEH4BAR3G0%2FoUKsm2Onprz7osiK8NxLvAev%2BqR5YyhwGNoc1aI4Yo2NXnsTwb6W5QSx%2BLg56xqcz99ml6pyQwM4HLLlH%2FQjgEBWJ8Mgwaq24KW8OgCQzeYL5sPfc43XULpB0TA%3D%3D";

        //ALGO_TRANSFORMATION_STRING = "AES/GCM/PKCS5Padding"

        try {
            // Load your own private and public keys
            PrivateKey privateKey = KeyLoader.loadPrivateKey("/Users/bytedance/Documents/Project/UOB/RSA/rsa_private.key");
            PublicKey publicKey = KeyLoader.loadPublicKeyFromCert("/Users/bytedance/Documents/Project/UOB/RSA/rsa_public.pem");

            // Encrypt and decrypt using your own keys
            //String encryptedText = rsaEncrypt(shortMessage, publicKey);
            String decryptedText = rsaDecrypt(encryptedText, privateKey);

            //System.out.println("Encrypted text = " + encryptedText);
            System.out.println("Decrypted text = " + decryptedText);

        } catch(Exception e) {
            System.out.println("Exception while encryption/decryption");
            e.printStackTrace();
        }
    }

    public static String rsaEncrypt(String message, Key publicKey) throws Exception {
        Cipher c = Cipher.getInstance(ALGORITHM_NAME + "/" + MODE_OF_OPERATION + "/" + PADDING_SCHEME);
        c.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherTextArray = c.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(cipherTextArray);
    }

    public static String rsaDecrypt(String encryptedMessage, Key privateKey) throws Exception {
        // URL-decode the encrypted message
        String urlDecodedMessage = URLDecoder.decode(encryptedMessage, "UTF-8");
        // Decode the URL-decoded Base64 string
        byte[] decodedBytes = Base64.getDecoder().decode(urlDecodedMessage);

        // Decrypt the decoded bytes
        Cipher cipher = Cipher.getInstance(ALGORITHM_NAME + "/" + MODE_OF_OPERATION + "/" + PADDING_SCHEME);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] plainText = cipher.doFinal(decodedBytes);

        return new String(plainText);
    }
}
