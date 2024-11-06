//SEGUNDA VERSION
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Servidor {
    
        public static void main(String[] args) throws IOException {
        int port = 8080; // Server port
        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Server listening on port " + port);
        ServerSocket finalServerSocket = serverSocket;
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                if (finalServerSocket != null && !finalServerSocket.isClosed()) {
                    finalServerSocket.close();
                    System.out.println("Server socket closed.");
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }));

    

        while (true) {
            Socket clientSocket = serverSocket.accept();
            new Thread(new Delegado(clientSocket)).start();
        }
    }
}
