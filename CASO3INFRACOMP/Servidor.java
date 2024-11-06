//SEGUNDA VERSION
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Servidor {
    
        public static void main(String[] args) throws IOException {
        int port = 8080; // Server port
        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Server listening on port " + port);
        
    

        while (true) {
            Socket clientSocket = serverSocket.accept();
            new Thread(new Delegado(clientSocket)).start();
        }
    }
}
