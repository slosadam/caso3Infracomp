import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Random;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PrivateKey;

import java.nio.file.Files;
import java.nio.file.Paths;

import java.security.spec.RSAPublicKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.Mac;

public class Cliente {

    public static final int PUERTO = 8080;
    public static final String SERVIDOR = "localhost";

    private static BigInteger privateExponentY;
    private static BigInteger sharedSecretKey;
    private static SecretKey symmetricKey;
    private static SecretKey hmacKey;
    
    
    public static void main(String[] args) throws Exception {
		
		Socket socket = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;
		
		System.out.println("Comienza cliente");
		
		try {
			socket = new Socket(SERVIDOR, PUERTO);
			escritor = new PrintWriter(socket.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		
		escritor.println("SECINIT");

        PublicKey publicKey = loadPublicKey("public.key");

        byte[] retoBytes = new byte[32];
        new SecureRandom().nextBytes(retoBytes); // Genero el reto

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] textoCifrado = cipher.doFinal(retoBytes);
        String textoCifradoBase64 = Base64.getEncoder().encodeToString(textoCifrado);
        escritor.println(textoCifradoBase64);
        
		String retoDesencriptado = lector.readLine();
        if (new String(retoBytes) == retoDesencriptado) {
            escritor.println("OK");

            BigInteger g = new BigInteger(lector.readLine()); //BitArray del BigInteger
            BigInteger p = new BigInteger(lector.readLine(),16); //El P viene en un string hex hay que transformalo
            BigInteger Gx = new BigInteger(lector.readLine()); //BitArray del BigInteger
            byte[] firma = Base64.getDecoder().decode(lector.readLine()); //Firma

            Signature verificador = Signature.getInstance("SHA1withRSA");
            verificador.initVerify(publicKey);

            verificador.update(p.toByteArray());
            verificador.update(g.toByteArray());
            verificador.update(Gx.toByteArray());
            
            if(verificador.verify(firma)) {
                escritor.println("OK");
                //LLEGA BIEN NO RUN
                ArrayList<BigInteger> devuelta =  crearKeySecretaCompartida(g, p, Gx, escritor);
                BigInteger privateExponentY = devuelta.get(0);
                BigInteger Gy = devuelta.get(1);
                escritor.println(Gy.toString()); // aqui la llave publica del cliente se manda al servidor
                sharedSecretKey = Gx.modPow(privateExponentY, p); // clave compartida secreta: K = (G^x)^y mod p
                deriveKeys(sharedSecretKey);

                Random random = new Random();
                int UID = random.nextInt(100);
                int package_id = random.nextInt(100);
                enviarDatosCifrados(String.valueOf(UID), String.valueOf(package_id), escritor);
                recibirYVerificarEstado(lector);
            }
            else {
                escritor.println("ERROR");
            }
        }
        else {
            escritor.println("ERROR");
        }
		
		socket.close();
		escritor.close();
		lector.close();
	}
    
    public static PublicKey loadPublicKey(String filename) throws Exception {
        String keyContent = new String(Files.readAllBytes(Paths.get(filename)))
                .replaceAll("\\n", "")
                .replaceAll("\\r", "");
                byte[] decodedKey = Base64.getDecoder().decode(keyContent);
                BigInteger modulus = new BigInteger(1, decodedKey);
                BigInteger exponent = BigInteger.valueOf(65537);

                RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                return keyFactory.generatePublic(spec);
    }

    public static ArrayList<BigInteger> crearKeySecretaCompartida(BigInteger g, BigInteger p, BigInteger Gx, PrintWriter escritor) {
        SecureRandom yRandom = new SecureRandom();
        BigInteger privateExponentY = new BigInteger(256, yRandom); // el exponente tiene 256 bits
        // clave pública cliente: G^y mod p
        BigInteger Gy = g.modPow(privateExponentY, p); 
        ArrayList<BigInteger> Devuelta = new ArrayList<>();
        Devuelta.add(privateExponentY);
        Devuelta.add(Gy);
        return Devuelta;

    }

    public static void deriveKeys(BigInteger sharedSecretKey) {
        try {
            byte[] kBytes = sharedSecretKey.toByteArray();
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] hash = sha512.digest(kBytes);

            // Dividir el hash en dos mitades
            byte[] symmetricKeyBytes = new byte[32]; // 256 bits para la clave simétrica
            byte[] hmacKeyBytes = new byte[32]; // 256 bits para la clave HMAC
            System.arraycopy(hash, 0, symmetricKeyBytes, 0, 32);
            System.arraycopy(hash, 32, hmacKeyBytes, 0, 32);

            // Crear las claves secretas
            SecretKey symmetricKey = new SecretKeySpec(symmetricKeyBytes, "AES");
            SecretKey hmacKey = new SecretKeySpec(hmacKeyBytes, "HmacSHA384");
            System.out.println("Clave simétrica derivada: " + new BigInteger(1, symmetricKey.getEncoded()).toString(16));
            System.out.println("Clave HMAC derivada: " + new BigInteger(1, hmacKey.getEncoded()).toString(16));
       
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void enviarDatosCifrados(String UID, String package_id, PrintWriter escritor){
        final int GCM_TAG_LENGTH = 128; // Define la longitud del tag de autenticación en bits    
        try {
            // Inicialización de cifrado AES en modo GCM
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] iv = new byte[16]; // Vector de inicialización para GCM
            new SecureRandom().nextBytes(iv);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, gcmSpec);

            // Cifrar UID
            byte[] UIDEncrypted = cipher.doFinal(UID.getBytes(StandardCharsets.UTF_8));
            String UIDEncryptedBase64 = Base64.getEncoder().encodeToString(UIDEncrypted);

            // Cifrar package_id
            cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, gcmSpec);
            byte[] packageIdEncrypted = cipher.doFinal(package_id.getBytes(StandardCharsets.UTF_8));
            String packageIdEncryptedBase64 = Base64.getEncoder().encodeToString(packageIdEncrypted);

            // Generar HMACs para ambos
            Mac hmac = Mac.getInstance("HmacSHA384");
            hmac.init(hmacKey);

            byte[] UIDHMAC = hmac.doFinal(UIDEncrypted);
            String UIDHMACBase64 = Base64.getEncoder().encodeToString(UIDHMAC);

            byte[] packageIdHMAC = hmac.doFinal(packageIdEncrypted);
            String packageIdHMACBase64 = Base64.getEncoder().encodeToString(packageIdHMAC);

            // Enviar al servidor: iv, datos cifrados y HMACs
            escritor.println(Base64.getEncoder().encodeToString(iv));
            escritor.println(UIDEncryptedBase64);
            escritor.println(UIDHMACBase64);
            escritor.println(packageIdEncryptedBase64);
            escritor.println(packageIdHMACBase64);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public static void recibirYVerificarEstado(BufferedReader lector) {
    try {
        // Leer IV en Base64 desde el servidor
        byte[] iv = Base64.getDecoder().decode(lector.readLine());
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        // Leer estado cifrado en Base64 desde el servidor
        byte[] estadoCifrado = Base64.getDecoder().decode(lector.readLine());

        // Leer HMAC del estado en Base64 desde el servidor
        byte[] estadoHMAC = Base64.getDecoder().decode(lector.readLine());

        // Verificar HMAC
        Mac hmac = Mac.getInstance("HmacSHA384");
        hmac.init(hmacKey);
        byte[] estadoHMACCalculado = hmac.doFinal(estadoCifrado);

        if (!MessageDigest.isEqual(estadoHMAC, estadoHMACCalculado)) {
            System.out.println("Error: HMAC del estado no coincide. El mensaje podría haber sido alterado.");
            return;
        }

        // Desencriptar estado
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, symmetricKey, gcmSpec);
        byte[] estadoDescifradoBytes = cipher.doFinal(estadoCifrado);
        String estadoDescifrado = new String(estadoDescifradoBytes, StandardCharsets.UTF_8);

        System.out.println("Estado del paquete recibido y verificado: " + estadoDescifrado);

    } catch (Exception e) {
        e.printStackTrace();
    }
}

}


    

