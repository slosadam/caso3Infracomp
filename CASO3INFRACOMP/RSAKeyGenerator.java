import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class RSAKeyGenerator {
    public static void main(String[] args) {
        try {
            // Generar el par de llaves
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(2048); // Tamaño de la llave
            KeyPair pair = keyPairGen.generateKeyPair();

            // Obtener las llaves pública y privada
            PublicKey publicKey = pair.getPublic();
            PrivateKey privateKey = pair.getPrivate();

            // Guardar la llave pública en un archivo
            saveKeyToFile("public.key.txt", publicKey.getEncoded());

            // Guardar la llave privada en un archivo
            saveKeyToFile("private.key.txt", privateKey.getEncoded());

            System.out.println("Las llaves se generaron y guardaron correctamente en archivos.");

        } catch (NoSuchAlgorithmException | IOException e) {
            System.err.println("Error al generar las llaves: " + e.getMessage());
        }
    }

    // Método para guardar una llave en un archivo
    private static void saveKeyToFile(String fileName, byte[] keyBytes) throws IOException {
        // Convertir a Base64 para una representación en texto
        String keyBase64 = Base64.getEncoder().encodeToString(keyBytes);

        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            fos.write(keyBase64.getBytes());
        }
    }
}

