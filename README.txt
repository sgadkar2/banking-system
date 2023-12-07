Name : Samsher Gadkary
Email ID : sgadkar2@binghamton.edu
Language used : Java
Tested on remote server : Yes

Steps to run the code : 
1) go to the directory containing the make file
2) type 'make' on terminal to run the make file. This will compile the code and create a .class file
4) type following command to start the Bank server
   java Bank <Port_Number>
5) type following command to connect Atm client to server
   java Atm <Server_Domain> <Port_Number>

Note : Code for performing public key encryption and decryption is present in AysmmetricCrytography.java file.
       Code for performing symmetric key encryption is present in Atm.java file. The method name is encrypt.
       Code for performing symmetric key decryption is present in Bank.java file. The method name is decrypt.