import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.interfaces.DHPrivateKey;

import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

import java.security.MessageDigest;
import java.security.Key;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.Mac;
import java.util.Arrays;


public class Delegado implements Runnable {

    private Socket clientSocket;
    private Key llave_1;
    private Key llave_2;

    public Delegado(Socket socket) {
        this.clientSocket = socket;
        this.llave_1 = new SecretKeySpec(new byte[1024], "AES");
        this.llave_2 = new SecretKeySpec(new byte[1024], "HmacSHA384");
    }

    @Override
    public void run() {
        try (BufferedReader lector = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
             PrintWriter escritor = new PrintWriter(clientSocket.getOutputStream(), true)) {
            
            handshake(lector, escritor);


            String gYString = lector.readLine(); //lee la llave publica que envio el cliente
            BigInteger Gy = new BigInteger(gYString);
            String hexP = "00858386226071a5e62bff2586d6b7116c8895ce22ee6a5a392a667f47ed92cc811b286ea68f4ba12618a2bd6985daa740b7e821ee2c30a3c98186e4093014b652823cf1e33a6597f3bc0a3b18e95520aeec3b6fbd9895a47e73e82f8d12776f6df5408596e95e2105c8bba3a2d5d18c4287f841991d1df0fb25514a60130b3677";
            BigInteger p = new BigInteger(hexP, 16); // hacemos p con el valor que nos dio en openssl
            BigInteger g = BigInteger.valueOf(2);; // valor de g, es arbitrario
            DHPrivateKey llavePrivMod = (DHPrivateKey) loadPrivateKey("path_to_private_key"); // Cargar la clave privada
            BigInteger Gx = g.modPow(llavePrivMod.getX(), p); // G^x mod 
            BigInteger sharedSecretKey = Gy.modPow(llavePrivMod.getX(), p);//llave compartida


             // Derivar las claves simétrica y HMAC usando SHA-512
             byte[] kBytes = sharedSecretKey.toByteArray();
             MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
             byte[] hash = sha512.digest(kBytes);

            //El hash se divide en dos
            byte[] symmetricKeyBytes = new byte[32]; // 256 bits para la clave simétrica
            byte[] hmacKeyBytes = new byte[32]; // 256 bits para la clave HMAC
            System.arraycopy(hash, 0, symmetricKeyBytes, 0, 32);
            System.arraycopy(hash, 32, hmacKeyBytes, 0, 32);

            // Crear las claves secretas
            SecretKey symmetricKey = new SecretKeySpec(symmetricKeyBytes, "AES");
            SecretKey hmacKey = new SecretKeySpec(hmacKeyBytes, "HmacSHA384");

            // Ahora puedes usar symmetricKey para cifrado y hmacKey para HMAC
            System.out.println("Clave simétrica derivada: " + new BigInteger(1, symmetricKey.getEncoded()).toString(16));
            System.out.println("Clave HMAC derivada: " + new BigInteger(1, hmacKey.getEncoded()).toString(16));

             // Leer datos encriptados y HMACs desde el cliente
       String ivBase64 = lector.readLine();
       byte[] iv = Base64.getDecoder().decode(ivBase64);

       String encryptedUIDBase64 = lector.readLine();
       byte[] encryptedUID = Base64.getDecoder().decode(encryptedUIDBase64);

       String uidHmacBase64 = lector.readLine();
       byte[] uidHmac = Base64.getDecoder().decode(uidHmacBase64);

       String encryptedPackageIdBase64 = lector.readLine();
       byte[] encryptedPackageId = Base64.getDecoder().decode(encryptedPackageIdBase64);

       String packageIdHmacBase64 = lector.readLine();
       byte[] packageIdHmac = Base64.getDecoder().decode(packageIdHmacBase64);

       if (verificarYProcesarDatos(encryptedUID, uidHmac, encryptedPackageId, packageIdHmac, iv)) {
        // Obtener estado del paquete y enviarlo al cliente encriptado
        String estadoPaquete = "Procesado correctamente"; // Ejemplo de estado
        enviarEstadoEncriptado(estadoPaquete, escritor, iv);
    } else {
        escritor.println("Error: HMAC no coincide o fallo de desencriptación.");
    }

        }
        catch (Exception e) {
            e.printStackTrace();
        }

    }

    public boolean verificarYProcesarDatos(byte[] encryptedUID, byte[] uidHmac, byte[] encryptedPackageId, 
                                           byte[] packageIdHmac, byte[] iv) throws Exception {
        // Verificar HMAC de UID
        Mac hmacSha384 = Mac.getInstance("HmacSHA384");
        hmacSha384.init(llave_2);

        byte[] computedUidHmac = hmacSha384.doFinal(encryptedUID);
        if (!Arrays.equals(computedUidHmac, uidHmac)) {
            System.out.println("HMAC de UID no coincide. Mensaje posiblemente alterado.");
            return false;
        }
        // Verificar HMAC de package_id
        byte[] computedPackageIdHmac = hmacSha384.doFinal(encryptedPackageId);
        if (!Arrays.equals(computedPackageIdHmac, packageIdHmac)) {
            System.out.println("HMAC de package_id no coincide. Mensaje posiblemente alterado.");
            return false;
        }
        // desencriptación de los datos usando AES-GCM con llave_1
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv); // 128 bits para el tag
        cipher.init(Cipher.DECRYPT_MODE, llave_1, gcmSpec);
        // Desencriptar UID
        byte[] uidBytes = cipher.doFinal(encryptedUID);
        String uid = new String(uidBytes);
        System.out.println("UID desencriptado: " + uid);
        // Desencriptar package_id
        cipher.init(Cipher.DECRYPT_MODE, llave_1, gcmSpec); // Re-iniciar para el package_id
        byte[] packageIdBytes = cipher.doFinal(encryptedPackageId);
        String packageId = new String(packageIdBytes);
        System.out.println("Package ID desencriptado: " + packageId);
        // Procesar el requerimiento: aquí puede implementar la lógica para buscar el estado del paquete
        return verificarEstadoPaquete(uid, packageId);
    }

    // Simulación de la consulta al estado del paquete (dummy function)
    private boolean verificarEstadoPaquete(String uid, String packageId) {
        System.out.println("Consultando estado del paquete con UID: " + uid + " y Package ID: " + packageId);
      
        return true; // Para simplificar
    }

    private void enviarEstadoEncriptado(String estado, PrintWriter escritor, byte[] iv) throws Exception {
        // Encriptar el estado del paquete
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, llave_1, gcmSpec);
        
        byte[] estadoEncriptado = cipher.doFinal(estado.getBytes());
        String estadoEncriptadoBase64 = Base64.getEncoder().encodeToString(estadoEncriptado);

        // Calcular HMAC del estado encriptado
        Mac hmacSha384 = Mac.getInstance("HmacSHA384");
        hmacSha384.init(llave_2);
        byte[] estadoHmac = hmacSha384.doFinal(estadoEncriptado);
        String estadoHmacBase64 = Base64.getEncoder().encodeToString(estadoHmac);

        // Enviar estado encriptado y HMAC al cliente
        escritor.println(estadoEncriptadoBase64);
        escritor.println(estadoHmacBase64);
    }

    public PrivateKey loadPrivateKey(String filename) throws Exception {
            byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(spec);
        }
    

    public boolean handshake(BufferedReader lector, PrintWriter escritor) throws Exception {
        PrivateKey privateKey = loadPrivateKey("");
            String requestLine = lector.readLine();
            if (requestLine == "SECINIT") {
                requestLine = lector.readLine(); //requestLine pasa a ser el reto encriptado
                byte[] texto_cifrado = Base64.getDecoder().decode(requestLine);

                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.DECRYPT_MODE, privateKey);

                byte[] texto_plano = cipher.doFinal(texto_cifrado);
                String reto_en_String = new String(texto_plano);
                escritor.println(reto_en_String);
                String respuesta_reto = lector.readLine();

                if (respuesta_reto == "OK") {

                    //Generar p, g, hellman y hacer la firma criptografica

                    String hexP = "00858386226071a5e62bff2586d6b7116c8895ce22ee6a5a392a667f47ed92cc811b286ea68f4ba12618a2bd6985daa740b7e821ee2c30a3c98186e4093014b652823cf1e33a6597f3bc0a3b18e95520aeec3b6fbd9895a47e73e82f8d12776f6df5408596e95e2105c8bba3a2d5d18c4287f841991d1df0fb25514a60130b3677";
                    BigInteger p = new BigInteger(hexP, 16); // hacemos p con el valor que nos dio en openssl
                    BigInteger g = BigInteger.valueOf(2);; // valor de g, es arbitrario

                    DHPrivateKey llaveprivadamodulo = (DHPrivateKey) privateKey;

                    BigInteger Gx = g.modPow(llaveprivadamodulo.getX(), g);

                    Signature signature = Signature.getInstance("SHA1withRSA");
                    signature.initSign(privateKey);
                    signature.update(p.toByteArray());
                    signature.update(g.toByteArray());
                    signature.update(Gx.toByteArray());

                    byte[] firmado = signature.sign();

                    escritor.println(g);
                    escritor.println(hexP);
                    escritor.println(Gx);
                    escritor.println(firmado);
                }
            }   
            return true; // lo puse para que no genere error el metodo
    }

}

