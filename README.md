# Simplified-DES-Cryptanalyser

##A Differential Cryptanalyser to crack Simplified DES cipher. 


###Encrypt.py                                                                           
####Script to encrypt a file using S-DES cipher.                                         
                                                                                     
How to run:                                                                          
Just execute this python script and provide the 10 bit key when prompted.            
                                                                                     
1. Default plaintext file: 'plaintext.txt'                                           
2. Default ciphertext file: 'ciphertext.txt'                                         
3. Both of these files are expected to be present in the current working directory.  
4. These names are listed on top of Encrypt.py and can be changed as desired.        
5. Electronic Codebook (ECB) mode of operation is used.                              



###Decrypt.py                                                                           
####Script to decrypt a file encrypted using S-DES cipher.                               
                                                                                     
How to run:                                                                          
Just execute this python script and provide the 10 bit key when prompted.            
                                                                                     
1. Default file from which encrypted text is taken : 'ciphertext.txt'                
2. Default file into which decrypted text is written into : 'decrypttext.txt'        
3. Both of these files are expected to be present in the current working directory.  
4. These names are listed on top of Encrypt.py and can be changed as desired.        
5. Electronic Codebook (ECB) mode of operation is used.                              




###crack.py
####Script to crack S-DES using differential cryptanalysis.                                           
                                                                                                  
How to run:                                                                                       
Just execute this python script and provide the 10 bit key when prompted.                         
                                                                                                  
1. Difference Pair Tables and Difference Distribution Tables can be printed by uncommenting       
   the code block towards the end of the code.                                                    
2. The code first finds round 2 key using input and output differentials, then uses it to find    
   round 1 key and main key.                                                                      
3. The code implements 2 methods of searching the round 2 key:                                    
    a. useCountSearch() finds round 2 key using the first non-zero count of matching first round  
       differentials starting from ((1,0),(1,0)) to ((15,3),(15,3))                               
    b. useProbSearch() finds the round 2 key by checking input and output SBox differences in the 
       order of decreasing product of probabilities.                                              
4. Any of the two can be used to find round 2 key. Just uncomment the line corresponding to one   
   method and comment the line corresponding to other method.                                     

