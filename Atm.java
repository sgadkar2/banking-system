import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class Atm {
    
     public static void main(String args[])
    {
        String serverName = args[0];
        int serverPort = Integer.parseInt(args[1]);

        //Security.addProvider(new Provider());
        System.setProperty("javax.net.ssl.trustStore","samsher.jts");
        System.setProperty("javax.net.ssl.trustStorePassword","123456");
        //System.setProperty("javax.net.debug","all");
        try
        {
            SSLSocketFactory sslsocketfactory = (SSLSocketFactory)SSLSocketFactory.getDefault();
            SSLSocket sslSocket = (SSLSocket)sslsocketfactory.createSocket(serverName,serverPort);

            System.out.println("Client Connected to Server");

            DataOutputStream outputStream = new DataOutputStream(sslSocket.getOutputStream());
            DataInputStream inputStream = new DataInputStream(sslSocket.getInputStream());

            Boolean isAuthenticated = false;
            while (true)
            {
                SecretKey symmetricKey = generateSymmetricKey();

                AsymmetricCryptography asymmetricCryptography = new AsymmetricCryptography();
                outputStream.writeUTF(asymmetricCryptography.encryptText(encodeSecretKey(symmetricKey)));

                System.out.println("Enter User ID : ");
                String userId = System.console().readLine();

                outputStream.writeUTF(encrypt(userId, symmetricKey));

                System.out.println("Enter password : ");
                String password = System.console().readLine();
                outputStream.writeUTF(encrypt(password, symmetricKey));
                
                String serverResponse = inputStream.readUTF();
                System.out.println(serverResponse);

                isAuthenticated = inputStream.readBoolean();;
                
                if(isAuthenticated){
                    break;
                }
            }

            while(isAuthenticated){
                System.out.println("Please select one of the following actions (enter 1, 2, or 3)");
                System.out.println("    1. Transfer money");
                System.out.println("    2. Check account balance");
                System.out.println("    3. Exit");

                String action = System.console().readLine();

                switch (action) {
                    case "1":

                        String accountType = "";
                        outputStream.writeUTF(action);
                        while(true){  
                            System.out.println("Please select an account (enter 1 or 2):");
                            System.out.println("    1. Savings");
                            System.out.println("    2. Checking");

                            accountType = System.console().readLine();
                            if(checkAccountType(accountType)){
                                break;
                            }

                            System.out.println("Incorrect input");
                        }
                        
                        int account = Integer.parseInt(accountType);
                        outputStream.writeInt(account);

                        System.out.println("Enter the receipient's ID: ");
                        String receipientId = System.console().readLine();
                        outputStream.writeUTF(receipientId);

                        System.out.println("Enter amount to be transfered");
                        String amount = System.console().readLine();
                        outputStream.writeUTF(amount);

                        System.out.println(inputStream.readUTF());

                        break;
                    
                    case "2":
                        
                        outputStream.writeUTF(action);

                        System.out.println("Your savings account balance: "+inputStream.readUTF());
                        System.out.println("Your checking account balance: "+inputStream.readUTF());

                        break;
                    case "3": 
                        outputStream.writeUTF(action);
                        isAuthenticated = false;
                        outputStream.close();
                        inputStream.close();
                        sslSocket.close();
                        break;
                        
                    default:
                        System.out.println("incorrect input");
                        break;
                }
            }


        }
        catch(Exception ex)
        {
            System.err.println("Error Happened : "+ex.toString());
        }
    }

    public static SecretKey generateSymmetricKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    public static String encrypt(String input, SecretKey key) throws Exception {
    
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder()
            .encodeToString(cipherText);
    }

    private static String encodeSecretKey(SecretKey secretKey) {
        byte[] encodedKeyBytes = secretKey.getEncoded();
        return Base64.getEncoder().encodeToString(encodedKeyBytes);
    }

    private static boolean checkAccountType(String accountType){

        boolean isValid = false;

        try {
            int account = Integer.parseInt(accountType);

            if(account == 1 || account == 2){
                isValid = true;
            }

        } catch (Exception e) {
            // TODO: handle exception
        }
        return isValid;
    }

}
