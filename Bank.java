import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class Bank {

    public static void main(String args[])
    {

        int port = Integer.parseInt(args[0]);
        
        System.setProperty("javax.net.ssl.keyStore","samsher.jks");
        System.setProperty("javax.net.ssl.keyStorePassword","123456");
        //System.setProperty("javax.net.debug","all");
        try
        {
            SSLServerSocketFactory sslServerSocketfactory = (SSLServerSocketFactory)SSLServerSocketFactory.getDefault();
            SSLServerSocket sslServerSocket = (SSLServerSocket)sslServerSocketfactory.createServerSocket(port);

            System.out.println("Server Started & Ready to accept Client Connection");

            while(true)
            {
                
                SSLSocket sslSocket = (SSLSocket)sslServerSocket.accept();

                DataInputStream inputStream = new DataInputStream(sslSocket.getInputStream());

                DataOutputStream outputStream = new DataOutputStream(sslSocket.getOutputStream());

                String userName = "";

                while(true){

                    String key = inputStream.readUTF();

                    //System.out.println(key);
                    AsymmetricCryptography asymmetricCryptography = new AsymmetricCryptography();
                    SecretKey symmetricKey = decodeSecretKey(asymmetricCryptography.decryptText(key));
                    
                    userName = decrypt(inputStream.readUTF(), symmetricKey);
                    System.out.println("User name is : " + userName);

                    String password = decrypt(inputStream.readUTF(), symmetricKey);
                    System.out.println("Password is : "+password);

                    if(checkUser(userName, password)){
                        outputStream.writeUTF("ID and password are correct");
                        outputStream.writeBoolean(true);
                        break;
                    }else{
                        outputStream.writeUTF("ID or password is incorrect");
                        outputStream.writeBoolean(false);
                    }
                }
                
                connectionSocket: while(true){
                    String action = inputStream.readUTF();
                    switch (action) {
                        case "1":
                            {  
                                int account = inputStream.readInt();
                                String receipientId = inputStream.readUTF();
                                Integer transferAmount = Integer.parseInt(inputStream.readUTF());

                                if(receipientIdExists(receipientId)){
                                    if(updateUserAmount(userName, account, transferAmount)){
                                        updateReceipientAmount(receipientId, account, transferAmount);
                                        //System.out.println(transferAmount);
                                        outputStream.writeUTF("your transaction is successful");
                                    }else{
                                        outputStream.writeUTF("Your account does not have enough funds");
                                    }
                                }else{
                                    outputStream.writeUTF("the recipient’s ID does not exist");
                                }
                                break;
                            }

                        case "2":
                            {
                                String filePath = "balance.txt";

                                try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
                                    
                                    String line;
                                    while ((line = reader.readLine()) != null) {
                                        String[] strArray = line.split("\\s+");

                                        if(strArray[0].equals(userName)){
                                            outputStream.writeUTF(strArray[1]);
                                            outputStream.writeUTF(strArray[2]);
                                        }
                                    }
                                }catch (IOException e) {
                                    System.err.println("An error occurred: " + e.getMessage());
                                }
                                break;
                            }

                        case "3":
                            {
                                outputStream.close();
                                inputStream.close();
                                sslSocket.close();

                                break connectionSocket;
                            }
                            
                        default:
                            break;
                        }
                
                }
            }

                
        }
        catch(Exception ex)
        {
            System.err.println("Error Happened : "+ex.toString());
        }
    }

    private static SecretKey decodeSecretKey(String encodedKey) {
        byte[] decodedKeyBytes = Base64.getDecoder().decode(encodedKey);
        return new javax.crypto.spec.SecretKeySpec(decodedKeyBytes, 0, decodedKeyBytes.length, "AES");
    }

    public static String decrypt(String cipherText, SecretKey key) throws Exception{

        try { 
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
            
            return new String(plainText);
        } catch (Exception e) {
            System.out.println("Exception is : "+e.getLocalizedMessage());
        }

        return null;
       
    }

    private static boolean checkUser(String userId, String password){

        boolean isValid = false;

        String filePath = "password.txt";

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] strArray = line.split("\\s+");

                if(strArray[0].equals(userId) && strArray[1].equals(password)){
                    return true;
                }
            }
        } catch (IOException e) {
            System.err.println("An error occurred: " + e.getMessage());
        }

        return isValid;
    }

    private static boolean receipientIdExists(String receipientId){

        boolean idExists = false;

        String filePath = "balance.txt";

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] strArray = line.split("\\s+");

                if(strArray[0].equals(receipientId)){
                    return true;
                }
            }
        }catch (IOException e) {
            System.err.println("An error occurred: " + e.getMessage());
        }
        return idExists;
    }

    private static boolean updateUserAmount(String userName, int accountType, int amount){

        boolean isSuccessful = false;
        try{
            String filePath = "balance.txt";
            StringBuilder fileContent = new StringBuilder();

            try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
                
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] strArray = line.split("\\s+");

                    if(strArray[0].equals(userName)){

                        if(accountType == 1){
                            int savingsAmount = Integer.parseInt(strArray[1]);

                            if(savingsAmount >= amount){
                                line = strArray[0] + " " + String.valueOf(savingsAmount - amount) + " " + strArray[2];
                            }else{
                                return false;
                            }
                        }else{
                            int checkingAmount = Integer.parseInt(strArray[2]);

                            if(checkingAmount >= amount){
                                line = strArray[0] + " " + strArray[1] + " " + String.valueOf(checkingAmount - amount);
                            }else{
                                return false;
                            }
                        }
                        isSuccessful = true;
                    }

                    fileContent.append(line).append(System.lineSeparator());
                }
            } 
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
                        writer.write(fileContent.toString());
            }
        }catch (IOException e) {
            System.err.println("An error occurred: " + e.getMessage());
        }

        return isSuccessful;
    }

    private static void updateReceipientAmount(String receipientId, int accountType, int amount){

        String filePath = "balance.txt";

        try {
            StringBuilder fileContent = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] strArray = line.split("\\s+");

                    if(strArray[0].equals(receipientId)){

                        if(accountType == 1){
                            int savingsAmount = Integer.parseInt(strArray[1]);
                            line = strArray[0] + " " + String.valueOf(savingsAmount + amount) + " " + strArray[2]; 
                        }else{
                            int checkingAmount = Integer.parseInt(strArray[2]);
                            line = strArray[0] + " " + strArray[1] + " " + String.valueOf(checkingAmount + amount);
                        }
                    }
                    fileContent.append(line).append(System.lineSeparator());
                }
            } 
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
                writer.write(fileContent.toString());
            }catch (IOException e) {
                System.err.println("An error occurred: " + e.getMessage());
            }
            
        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
        }

        

    }
    
}