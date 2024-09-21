import java.security.KeyPairGenerator;
import java.security.PrivateKey ;
import java.security.PublicKey ;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Base64 ;
import javax.crypto.Cipher ;
import java.lang.Exception ;
import java.security.Key ;
import java.security.KeyPair ;

import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.security.cert.Certificate;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

public class SecuredRSAUsage {

       static String privateKeyString = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "-----END RSA PRIVATE KEY-----\n";


       static String publicKeyString = "-----BEGIN CERTIFICATE-----\n" +
                "-----END CERTIFICATE-----";

        static int RSA_KEY_LENGTH = 4096;
        static String ALGORITHM_NAME = "RSA" ;
        static String PADDING_SCHEME = "OAEPWITHSHA-512ANDMGF1PADDING" ;
        static String MODE_OF_OPERATION = "ECB" ; // This essentially means none behind the scene

        static PublicKey publicKey;
        static PrivateKey privateKey;

        public static void main(String args[]) {
                String shortMessage = "Zakky Ganteng";



                try {
                        publicKey = loadPublicKeyFromString(publicKeyString);
                } catch (Exception e) {
                        System.out.println("Exception while load public") ;
                        e.printStackTrace() ;
                }

                try {
                        privateKey = loadPrivateKeyFromString(privateKeyString);
                } catch (Exception e) {
                        System.out.println("Exception while load private") ;
                        e.printStackTrace() ;
                }

                try {

                // Generate Key Pairs
                KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance(ALGORITHM_NAME) ;
                rsaKeyGen.initialize(RSA_KEY_LENGTH) ;
                KeyPair rsaKeyPair = rsaKeyGen.generateKeyPair();


                String testDecrypt;

                testDecrypt = "sJ3OIIoyL2TaQ1KL6UvY63YNPSkdw6VS3%2FDexKLO%2Fw2K3u5btF2ylQEWHPKOMS39Q%2F3iSz9eccldM63QjDtUiFHyT8ZJ%2FchXHsZYCPP0A6X%2Fi4XCHID%2BreAjN%2F0aaz1kr%2FFhvhw1gF9Ig89O3ZTHy4N3VN08Ap8KLVURvYQmwgPZtH3y28zAywcS40PaaENbBhPWMIXLr%2BIXkbjTtEH4BAR3G0%2FoUKsm2Onprz7osiK8NxLvAev%2BqR5YyhwGNoc1aI4Yo2NXnsTwb6W5QSx%2BLg56xqcz99ml6pyQwM4HLLlH%2FQjgEBWJ8Mgwaq24KW8OgCQzeYL5sPfc43XULpB0TA%3D%3D";



                    String encryptedText = rsaEncrypt(shortMessage, publicKey);

                    String decryptedText = rsaDecrypt(Base64.getDecoder().decode(encryptedText), privateKey) ;
                    String decryptedText2 = rsaDecrypt(Base64.getDecoder().decode(testDecrypt), privateKey) ;

                    System.out.println("Encrypted text = " + encryptedText) ;
                    System.out.println("Decrypted text = " + decryptedText) ;
                    System.out.println("Decrypted text = " + decryptedText2) ;


                } catch(Exception e) {System.out.println("Exception while encryption/decryption") ;e.printStackTrace() ; }


        }

        public static PrivateKey loadPrivateKeyFromString(String privateKeyPEM) throws Exception {
                PemReader pemReader = new PemReader(new StringReader(privateKeyPEM));
                PemObject pemObject = pemReader.readPemObject();
                pemReader.close();

                ASN1Primitive asn1PrivateKey = ASN1Primitive.fromByteArray(pemObject.getContent());
                RSAPrivateKey rsa = RSAPrivateKey.getInstance(asn1PrivateKey);

                RSAPrivateKeySpec spec = new RSAPrivateKeySpec(rsa.getModulus(), rsa.getPrivateExponent());
                KeyFactory factory = KeyFactory.getInstance("RSA");
                return factory.generatePrivate(spec);
        }

        public static PublicKey loadPublicKeyFromString(String publicKeyPEM) throws Exception {
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                PemReader pemReader = new PemReader(new StringReader(publicKeyPEM));
                byte[] content = pemReader.readPemObject().getContent();
                pemReader.close();

                X509Certificate certificate = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(content));
                return certificate.getPublicKey();
        }

        public static String rsaEncrypt(String message, Key publicKey) throws Exception {
                Cipher c = Cipher.getInstance(ALGORITHM_NAME + "/" + MODE_OF_OPERATION + "/" + PADDING_SCHEME) ;

                c.init(Cipher.ENCRYPT_MODE, publicKey) ;

                byte[] cipherTextArray = c.doFinal(message.getBytes()) ;

                return Base64.getEncoder().encodeToString(cipherTextArray) ;

        }


        public static String rsaDecrypt(byte[] encryptedMessage, Key privateKey) throws Exception {
                Cipher c = Cipher.getInstance(ALGORITHM_NAME + "/" + MODE_OF_OPERATION + "/" + PADDING_SCHEME) ;
                c.init(Cipher.DECRYPT_MODE, privateKey);
                byte[] plainText = c.doFinal(encryptedMessage);

                return new String(plainText) ;

        }
}
