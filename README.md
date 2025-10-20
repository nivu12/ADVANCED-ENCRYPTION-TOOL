# ADVANCED-ENCRYPTION-TOOL

*COMPANY*: CODTECH IT SOLUTIONS

*NAME*: NIVYA ANTONY

*INTERN ID*: CT04DY2625

*DOMAIN*: CYBER SECURITY AND ETHICAL HACKING

*DURATION*: 4 WEEKS

*MENTOR*: NEELA SANTHOSH

## The final task for Cybersecurity and Ethical Hacking internship was to create an advanced encryption tool with a user friendly interface. It was instructed to build a tool that can encrypt and decrypt files using advanced algorithms like *AES-256* and deliver a robust encryption application with a user-friendly interface.
The main objective of this task is to understand the working of symmetric key encryption using the AES-256 algorithm. The same passkey is used to encrypt and decrypt the files. This tool can prevent unauthorized access to sensitive information.
For encryption and decryption which is our ultimate aim , AES-256 algorithm was used by installing *PyCryptodome*. This algorithm is resistant to brute-force attacks due to large key size because it uses a 256-bit key. At first encrypted files were saved seperately later modified to replace the encrypted file over the original file. I thought this should add better integrity. As of now it asks the user whether to replace or create new encrypted file. Used *PBKDF2* to derive strong keys from the user's password. Encrypted files are saved with the *.enc* extension and decrypted files can be saved with any name and it's original extension. 
The library *tkinter* was used to design the graphical user interface (GUI). *Pillow(PIL)* library was used to load and display background images in the GUI. From the GUI user selects a file and enters a password. AES encrypt the file and saves it with '.enc' extension. The user can choose to replace the original file or keep both versions. Next the user selects an encrypted file and enter the same password used during encryption if the password is correct it decrypts the file to original format or else outputs an alert box.
Finally the task is done and the decrypted file apears on the project folder.
With this final task this project marks the completion of my 4 week Cybersecurity and Ethical Hacking internship. This tasks strengthened my self learning ability and confidence to work independently on security related projects in the future. Thank you.
